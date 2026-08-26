package runner

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.ngrok.com/muxado"
)

// socketpairTCP returns the ends of an AF_UNIX SOCK_STREAM socketpair.
// Unlike net.Pipe (synchronous shared-buffer handoff), real sockets buffer
// independently — mirroring the production transport and avoiding muxado
// framing races inherent to net.Pipe (see proxy test notes, WP-M2).
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

// pipeSessions wires two muxado sessions over a real socketpair so protocol
// tests run without bwrap between guest client and host runner.
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
