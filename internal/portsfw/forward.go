package portsfw

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.ngrok.com/muxado"
)

// DefaultDialTimeout bounds the guest-side connect to the sandbox service.
const DefaultDialTimeout = 5 * time.Second

// DialFunc opens the guest-side connection to a sandbox loopback target.
// Tests inject stubs; production uses (*net.Dialer).DialContext.
type DialFunc func(network, addr string) (net.Conn, error)

func defaultDial() DialFunc {
	var d net.Dialer
	return func(network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultDialTimeout)
		defer cancel()
		return d.DialContext(ctx, network, addr)
	}
}

// ServeGuest serves the guest end of channel E until sess dies: every
// incoming stream carries a 2-byte target header (EncodeTarget), then raw
// bytes. Targets outside allowed are closed WITHOUT dialing — deny-by-
// default on the sandbox side as well (THREAT_MODEL §5.8: undeclared ports
// never expose). A nil dial selects the production loopback dialer.
//
// The guest forwarder only ever dials what the host client asked for and
// returns answers to that stream — no new outbound path is created.
func ServeGuest(ctx context.Context, sess muxado.Session, allowed map[int]bool, dial DialFunc) error {
	if dial == nil {
		dial = defaultDial()
	}
	// muxado's Accept does not wake on remote transport death alone;
	// cancelling closes the local session so Accept and in-flight streams
	// unwind deterministically (same teardown order as channel A: session
	// first, then everything riding on it).
	go func() {
		<-ctx.Done()
		_ = sess.Close()
	}()
	for {
		stream, err := sess.Accept()
		if err != nil {
			return fmt.Errorf("accept channel-E stream: %w", err)
		}
		go handleGuestStream(stream, allowed, dial)
	}
}

func handleGuestStream(stream net.Conn, allowed map[int]bool, dial DialFunc) {
	defer func() { _ = stream.Close() }()

	target, err := DecodeTarget(stream)
	if err != nil || !allowed[target] {
		// Undeclared or malformed: close immediately (fail-closed).
		return
	}
	upstream, err := dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(target)))
	if err != nil {
		return
	}
	tunnel(stream, upstream)
}

// Forward runs the host side of channel E for ONE declared entry: it
// accepts connections on ln (bound to 127.0.0.1 by the caller) and tunnels
// each through sess to guestPort inside the sandbox. Blocking; unblocks
// when ln or sess closes.
func Forward(sess muxado.Session, ln net.Listener, guestPort int) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("channel-E accept %s: %w", ln.Addr(), err)
		}
		stream, err := sess.Open()
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("channel-E open stream: %w", err)
		}
		var hdr [2]byte
		if err := EncodeTarget(hdr[:], guestPort); err != nil {
			_ = conn.Close()
			_ = stream.Close()
			continue // unreachable for validated configs, but never leak
		}
		if _, err := stream.Write(hdr[:]); err != nil {
			_ = conn.Close()
			_ = stream.Close()
			continue
		}
		go tunnel(conn, stream)
	}
}

// tunnel copies both directions until either side ends; the first finished
// direction closes BOTH ends — half-close alone would leave the opposite
// Copy blocked forever (same lesson as channel A, WP-M2 Umsetzungsnotiz 4).
func tunnel(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeBoth() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeBoth() }()
	wg.Wait()
}
