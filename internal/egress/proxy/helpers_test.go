package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.ngrok.com/muxado"
)

// socketpairTCP returns the ends of an AF_UNIX SOCK_STREAM socketpair as
// generic read-write closers. Unlike net.Pipe (synchronous, shared-buffer
// handoff), real sockets buffer independently — mirroring production.
func socketpairTCP(t *testing.T) (a, b io.ReadWriteCloser) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a = os.NewFile(uintptr(fds[0]), "test-sock-a")
	b = os.NewFile(uintptr(fds[1]), "test-sock-b")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// echoServer starts a TCP server answering every byte with itself; used as
// fake tunnel target and fake upstream.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() // #nosec G307 -- best-effort close in test server
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// pipeSessions wires two muxado sessions over a real socketpair so protocol
// tests run without bwrap between guest and host.
func pipeSessions(t *testing.T) (client, server muxado.Session) {
	t.Helper()
	hostEnd, guestEnd := socketpairTCP(t)
	client = muxado.Client(guestEnd, nil)
	server = muxado.Server(hostEnd, nil)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// fakeDial routes every address to a fixed test endpoint (stand-in for
// DNS/hosts resolution inside protocol tests).
func fakeDial(target string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "tcp", target)
	}
}

// openStream opens one session stream with cleanup attached.
func openStream(t *testing.T, sess muxado.Session) net.Conn {
	t.Helper()
	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

// speakCONNECT speaks one CONNECT request on a fresh stream and returns the
// response plus the stream (usable as raw tunnel when the status is 200).
func speakCONNECT(t *testing.T, sess muxado.Session, target string) (*http.Response, net.Conn) {
	t.Helper()
	stream := openStream(t, sess)
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := stream.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, stream
}

// startServer runs Serve in the background and fails the test on early
// termination or when Serve survives the session close.
func startServer(t *testing.T, sess muxado.Session, cfg Server) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Serve(sess, cfg) }()
	t.Cleanup(func() {
		_ = sess.Close() // unblocks Accept before we wait for Serve
		select {
		case err := <-done:
			if err != nil && !strings.Contains(err.Error(), "closed") &&
				!strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "use of closed") {
				t.Errorf("Serve terminated unexpectedly: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not return after session close")
		}
	})
}

// portOf extracts the numeric port from a "host:port" address (test helper).
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

// runtimeNumGoroutine indirection keeps the leak check testable.
func runtimeNumGoroutine() int { return runtime.NumGoroutine() }
