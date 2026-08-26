package portsfw

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.ngrok.com/muxado"
)

// socketpairTCP returns the ends of an AF_UNIX SOCK_STREAM socketpair.
// muxado's framer dataraces over net.Pipe (synchronous shared-buffer
// handover), so protocol tests use real sockets — same reasoning as the
// channel-A tests (WP-M2 Umsetzungsnotiz 5).
func socketpairTCP(t *testing.T) (a, b *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a = os.NewFile(uintptr(fds[0]), "portfw-test-a")
	b = os.NewFile(uintptr(fds[1]), "portfw-test-b")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// echoServer starts a tiny TCP echo server on 127.0.0.1:0 and returns its
// address; every received byte sequence is echoed back per connection.
func echoServer(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr()
}

func readWithTimeout(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, n)
	got, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read %d bytes: %v (got %d)", n, err, got)
	}
	return buf
}

// TestChannelE_EndToEnd tunnels a host-side TCP connection through a real
// muxado session and the guest forwarder into a loopback echo server —
// the full data path of channel E without bwrap.
func TestChannelE_EndToEnd(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)
	echoAddr := echoServer(t)
	target := echoAddr.(*net.TCPAddr).Port

	allowed, err := ParseAllowed(FormatAllowed([]ResolvedPort{{Guest: target}}))
	if err != nil {
		t.Fatalf("parse allowed: %v", err)
	}

	// Guest side: refuses undeclared targets, dials declared ones on the
	// sandbox loopback.
	gctx, gcancel := context.WithCancel(context.Background())
	defer gcancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeGuest(gctx, muxado.Server(guestEnd, nil), allowed, nil)
	}()

	// Host side: one listener per declared entry, forwarding to its guest
	// target over the session.
	sess := muxado.Client(hostEnd, nil)
	defer func() { _ = sess.Close() }()

	fwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forwarder listen: %v", err)
	}
	defer func() { _ = fwLn.Close() }()
	go func() { _ = Forward(sess, fwLn, target) }()

	conn, err := net.Dial(fwLn.Addr().Network(), fwLn.Addr().String())
	if err != nil {
		t.Fatalf("host client dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("ping-through-channel-e")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := readWithTimeout(t, conn, len(payload))
	if string(got) != string(payload) {
		t.Errorf("echo = %q, want %q", got, payload)
	}

	// Second request on the same infrastructure proves the accept loops
	// keep serving (fork-per-connection semantics).
	conn2, err := net.Dial(fwLn.Addr().Network(), fwLn.Addr().String())
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer func() { _ = conn2.Close() }()
	if _, err := conn2.Write([]byte("x")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := readWithTimeout(t, conn2, 1); string(got) != "x" {
		t.Errorf("second echo = %q, want x", got)
	}

	// Teardown order per WP-M2 note 3: session first (unblocks streams),
	// then cancel the accept loop.
	_ = sess.Close()
	gcancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("guest forwarder did not exit after session close (goroutine leak)")
	}
}

// TestServeGuest_RefusesUndeclaredTarget pins THREAT_MODEL §5.8 deny-by-
// default on the guest side: targets outside the allowlist get no dial at
// all — the stream is closed immediately.
func TestServeGuest_RefusesUndeclaredTarget(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)

	dialed := 0
	gctx, gcancel := context.WithCancel(context.Background())
	defer gcancel()
	go func() {
		_ = ServeGuest(gctx, muxado.Server(guestEnd, nil), map[int]bool{3000: true},
			func(network, addr string) (net.Conn, error) {
				dialed++
				return net.Dial(network, addr)
			})
	}()

	sess := muxado.Client(hostEnd, nil)
	defer func() { _ = sess.Close() }()

	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	var hdr [2]byte
	if err := EncodeTarget(hdr[:], 9999); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := stream.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := stream.Read(buf); err == nil {
		t.Error("undeclared target must be closed by the guest, got data/EOF-free read")
	}
	if dialed != 0 {
		t.Errorf("guest dialed %d times for an undeclared target", dialed)
	}
}
