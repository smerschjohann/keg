// Package portsfw implements host and guest port forwarding mechanisms.
// This file implements the inbound forward channel (Kanal F): services running
// on the host or in the network are exposed on the sandbox loopback interface.
package portsfw

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/smerschjohann/keg/internal/config"

	"golang.ngrok.com/muxado"
)

// FormatForwardHosts converts a slice of ForwardHostSpec into a comma-separated string
// suitable for passing via an environment variable to the guest.
func FormatForwardHosts(specs []config.ForwardHostSpec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		parts = append(parts, fmt.Sprintf("%d:%s:%d", s.GuestPort, s.TargetHost, s.TargetPort))
	}
	return strings.Join(parts, ",")
}

// ParseForwardHostsEnv parses the comma-separated environment string back into specs.
func ParseForwardHostsEnv(envVal string) ([]config.ForwardHostSpec, error) {
	if strings.TrimSpace(envVal) == "" {
		return nil, nil
	}
	parts := strings.Split(envVal, ",")
	out := make([]config.ForwardHostSpec, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		spec, err := config.ParseForwardHostFlag(p)
		if err != nil {
			return nil, fmt.Errorf("parse forward host %q: %w", p, err)
		}
		out = append(out, spec)
	}
	return out, nil
}

// ServeHostForwarder serves the host end of channel F: every incoming stream
// from the sandbox guest carries a 2-byte target header (guest port requested),
// which is matched against the allowed whitelist. If allowed, it connects to
// the target host:port on the host side and tunnels data.
func ServeHostForwarder(ctx context.Context, sess muxado.Session, allowed []config.ForwardHostSpec, dial DialFunc) error {
	if dial == nil {
		dial = defaultDial()
	}

	targetMap := make(map[int]config.ForwardHostSpec, len(allowed))
	for _, s := range allowed {
		targetMap[s.GuestPort] = s
	}

	go func() {
		<-ctx.Done()
		_ = sess.Close()
	}()

	for {
		stream, err := sess.Accept()
		if err != nil {
			return fmt.Errorf("accept channel-F stream: %w", err)
		}
		go handleHostStream(stream, targetMap, dial)
	}
}

func handleHostStream(stream net.Conn, targetMap map[int]config.ForwardHostSpec, dial DialFunc) {
	defer func() { _ = stream.Close() }()

	target, err := DecodeTarget(stream)
	if err != nil {
		return
	}
	spec, ok := targetMap[target]
	if !ok {
		// Undeclared target: fail-closed immediately
		return
	}

	targetAddr := net.JoinHostPort(spec.TargetHost, strconv.Itoa(spec.TargetPort))
	upstream, err := dial("tcp", targetAddr)
	if err != nil {
		return
	}
	tunnel(stream, upstream)
}

// ForwardGuest runs on the guest side of channel F for ONE declared entry:
// it accepts connections on ln (bound to 127.0.0.1:<guestPort> in the sandbox)
// and tunnels each connection through sess to the host forwarder.
func ForwardGuest(sess muxado.Session, ln net.Listener, guestPort int) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("channel-F accept %s: %w", ln.Addr(), err)
		}
		stream, err := sess.Open()
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("channel-F open stream: %w", err)
		}
		var hdr [2]byte
		if err := EncodeTarget(hdr[:], guestPort); err != nil {
			_ = conn.Close()
			_ = stream.Close()
			continue
		}
		if _, err := stream.Write(hdr[:]); err != nil {
			_ = conn.Close()
			_ = stream.Close()
			continue
		}
		go tunnel(conn, stream)
	}
}

// ServeGuestForwarders sets up listeners for all declared forward_hosts inside the sandbox
// and runs ForwardGuest in the background for each.
func ServeGuestForwarders(ctx context.Context, sess muxado.Session, specs []config.ForwardHostSpec) ([]net.Listener, error) {
	var listeners []net.Listener
	cleanup := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}

	for _, spec := range specs {
		var lc net.ListenConfig
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.GuestPort))
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("listen sandbox forward port %d: %w", spec.GuestPort, err)
		}
		listeners = append(listeners, ln)
		go func(l net.Listener, port int) {
			_ = ForwardGuest(sess, l, port)
		}(ln, spec.GuestPort)
	}

	go func() {
		<-ctx.Done()
		cleanup()
	}()

	return listeners, nil
}
