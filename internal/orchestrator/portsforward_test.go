package orchestrator

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/portsfw"

	"golang.ngrok.com/muxado"
)

// echoListener starts a tiny TCP echo server on 127.0.0.1:0.
func echoListener(t *testing.T) int {
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
	return ln.Addr().(*net.TCPAddr).Port
}

// bindLoopback mirrors buildRunPlan's dynamic allocation: bind 127.0.0.1:0,
// the listener IS the port reservation. Returns the listener interface
// (not a pointer — ResolvedPort.Listener stores it by value).
func bindLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback: %v", err)
	}
	return ln
}

// TestSandbox_StartPortsForward verifies the host side of channel E:
// declared entries are served as loopback listeners on the FDPorts channel;
// a host client reaches the sandbox loopback service through the tunnel.
// Closing the sandbox releases the listeners and unwinds the channel.
func TestSandbox_StartPortsForward(t *testing.T) {
	hostEnd, guestEnd, err := Socketpair()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer guestEnd.Close() // #nosec G307 -- test teardown order checked explicitly below

	target := echoListener(t)

	// Guest side of the channel: forwarder with the declared allowlist —
	// exactly what startConfiguredBridges wires from the KEG_PORTS
	// marker.
	gctx, gcancel := context.WithCancel(context.Background())
	defer gcancel()
	guestDone := make(chan struct{})
	go func() {
		defer close(guestDone)
		_ = portsfw.ServeGuest(gctx, muxado.Client(guestEnd, nil),
			map[int]bool{target: true}, nil)
	}()

	fwLn := bindLoopback(t)
	sb := &Sandbox{hostEnds: []*os.File{nil, nil, nil, hostEnd}}
	err = sb.StartPortsForward([]portsfw.ResolvedPort{{
		Name:     "dev",
		Guest:    target,
		HostPort: fwLn.Addr().(*net.TCPAddr).Port,
		Listener: fwLn,
	}})
	if err != nil {
		t.Fatalf("StartPortsForward: %v", err)
	}

	conn, err := net.Dial("tcp", fwLn.Addr().String())
	if err != nil {
		t.Fatalf("host client dial: %v", err)
	}
	payload := []byte("channel-e-probe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
	_ = conn.Close()

	// Close must release the forwarded listeners AND unwind the channel.
	sb.Close()
	if _, err := net.DialTimeout("tcp", fwLn.Addr().String(), 500*time.Millisecond); err == nil {
		t.Error("listener still accepting after Close")
	}
	gcancel()
	select {
	case <-guestDone:
	case <-time.After(3 * time.Second):
		t.Fatal("guest forwarder did not exit (goroutine leak)")
	}
}

// TestStartPortsForward_StaticPortBinding fails loudly when a static host
// port cannot be bound (CONCEPT.md §4.9 lifecycle rule: Kollision ⇒ klarer
// Fehler).
func TestStartPortsForward_StaticPortBinding(t *testing.T) {
	hostEnd, guestEnd, err := Socketpair()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer guestEnd.Close() // #nosec G307 -- test cleanup
	defer hostEnd.Close()  // #nosec G307 -- test cleanup

	occupied := bindLoopback(t)

	sb := &Sandbox{hostEnds: []*os.File{nil, nil, nil, hostEnd}}
	err = sb.StartPortsForward([]portsfw.ResolvedPort{
		{Guest: 3000, HostPort: occupied.Addr().(*net.TCPAddr).Port},
	})
	if err == nil {
		t.Fatal("binding an occupied static port must fail")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("error should name the bind address: %v", err)
	}
}

// TestSandbox_StartPortsForward_NoChannel errors clearly when channel E is
// not available (e.g. direct-bwrap test fallbacks).
func TestSandbox_StartPortsForward_NoChannel(t *testing.T) {
	sb := &Sandbox{}
	if err := sb.StartPortsForward(nil); err == nil {
		t.Fatal("missing channel must error, not silently succeed")
	}
}
