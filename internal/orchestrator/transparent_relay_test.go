package orchestrator

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.ngrok.com/muxado"
)

// fakeOrigin serves one muxado session like the host-side policy proxy:
// it answers every CONNECT with 200 and echoes tunneled bytes back.
func fakeOrigin(t *testing.T, wantTargets chan<- string, hostEnd io.ReadWriteCloser) {
	t.Helper()
	sess := muxado.Server(hostEnd, nil)
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go func(stream io.ReadWriteCloser) {
			defer stream.Close()
			req, err := http.ReadRequest(bufio.NewReader(stream))
			if err != nil {
				return
			}
			wantTargets <- req.Host
			_, _ = io.WriteString(stream, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = io.Copy(stream, stream) // echo tunnel
		}(stream)
	}
}

// startTestRelay runs the transparent relay against a test session and an
// injected original-destination lookup.
func startTestRelay(t *testing.T, wantTargets chan<- string, origDst func(net.Conn) (net.IP, int, bool)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostEnd := os.NewFile(uintptr(fds[0]), "test-relay-host")
	guestEnd := os.NewFile(uintptr(fds[1]), "test-relay-guest")
	t.Cleanup(func() {
		_ = hostEnd.Close()
		_ = guestEnd.Close()
	})
	go fakeOrigin(t, wantTargets, hostEnd)
	go func() { _ = serveTransparent(ln, muxado.Client(guestEnd, nil), origDst) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestRelay_RawTCPPassthroughUsesOriginalDest(t *testing.T) {
	targets := make(chan string, 16)
	ln := startTestRelay(t, targets, func(net.Conn) (net.IP, int, bool) {
		return net.ParseIP("10.1.2.3"), 9000, true
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PING\n")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != "PING\n" {
		t.Fatalf("echo = %q", buf[:n])
	}
	select {
	case got := <-targets:
		if got != "10.1.2.3:9000" {
			t.Fatalf("CONNECT target = %q, want 10.1.2.3:9000", got)
		}
	default:
		t.Fatal("relay never sent a CONNECT")
	}
}

func TestRelay_RawWithoutOriginalDestFailsClosed(t *testing.T) {
	targets := make(chan string, 16)
	ln := startTestRelay(t, targets, func(net.Conn) (net.IP, int, bool) { return nil, 0, false })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PING\n")

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	if n, _ := conn.Read(buf); n > 0 {
		t.Fatalf("fail-closed relay must not answer, got %q", buf[:n])
	}
	select {
	case got := <-targets:
		t.Fatalf("fail-closed relay sent CONNECT %q", got)
	default:
	}
}

func TestRelay_TLSWithoutSNIFailsClosed(t *testing.T) {
	targets := make(chan string, 16)
	ln := startTestRelay(t, targets, func(net.Conn) (net.IP, int, bool) {
		return net.ParseIP("10.1.2.3"), 443, true
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// TLS-looking first byte, but no parseable ClientHello/SNI follows.
	fmt.Fprintf(conn, "\x16garbage-not-a-hello\x00\x00")

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	if n, _ := conn.Read(buf); n > 0 {
		t.Fatalf("TLS without SNI must be closed, got %q", buf[:n])
	}
	select {
	case got := <-targets:
		t.Fatalf("SNI-less TLS sent CONNECT %q", got)
	default:
	}
}

func TestRelay_ClientHelloSplicesToSNIHost(t *testing.T) {
	targets := make(chan string, 16)
	ln := startTestRelay(t, targets, func(net.Conn) (net.IP, int, bool) {
		return net.ParseIP("10.9.9.9"), 4443, true
	})

	hello := mustHex(realHelloHex) // golden ClientHello with SNI
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	var got string
	select {
	case got = <-targets:
	case <-time.After(5 * time.Second):
		t.Fatal("no CONNECT for valid ClientHello")
	}
	// SNI path pins the port from the pre-NAT destination when available;
	// the hostname decides policy host-side.
	if !strings.HasPrefix(got, "daily-cloudcode-pa.googleapis.com:") {
		t.Fatalf("CONNECT target = %q, want SNI host prefix", got)
	}
}
