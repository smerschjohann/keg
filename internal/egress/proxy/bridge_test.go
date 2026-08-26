package proxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.ngrok.com/muxado"
)

// startEchoPeer accepts streams on the host-side session and echoes the
// first received chunk back with a prefix, simulating the remote proxy
// endpoint (single Read, no EOF wait — tunnels are bidirectional).
func startEchoPeer(t *testing.T, sess muxado.Session) {
	t.Helper()
	go func() {
		for {
			stream, err := sess.Accept()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close() // #nosec G307 -- best-effort close in test peer
				buf := make([]byte, 4096)
				n, err := s.Read(buf)
				if err != nil && n == 0 {
					return
				}
				_, _ = io.WriteString(s, "peer:"+string(buf[:n])+"\n")
			}(stream)
		}
	}()
}

func TestBridge_PipesBytesTransparently(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)
	clientSess := muxado.Client(guestEnd, nil)
	serverSess := muxado.Server(hostEnd, nil)
	t.Cleanup(func() {
		_ = clientSess.Close()
		_ = serverSess.Close()
	})
	startEchoPeer(t, serverSess)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	bridge := NewBridge(clientSess, ln)
	serveErr := make(chan error, 1)
	go func() { serveErr <- bridge.Serve() }()
	t.Cleanup(func() {
		_ = bridge.Close()
		select {
		case err := <-serveErr:
			if err != nil && !strings.Contains(err.Error(), "closed") &&
				!strings.Contains(err.Error(), "use of closed") {
				t.Errorf("Serve terminated unexpectedly: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("bridge Serve did not return after Close")
		}
	})

	// A naive client (like curl talking to its HTTP_PROXY) connects via
	// plain TCP; the bridge must relay bytes 1:1 without interpreting them.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer conn.Close() // #nosec G307 -- test cleanup
	payload := "CONNECT proxy.golang.org:443 HTTP/1.1\r\n\r\n"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(resp) != "peer:"+payload+"\n" {
		t.Fatalf("payload not piped transparently: %q", resp)
	}
}

func TestBridge_ConcurrentConnections(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)
	clientSess := muxado.Client(guestEnd, nil)
	serverSess := muxado.Server(hostEnd, nil)
	t.Cleanup(func() {
		_ = clientSess.Close()
		_ = serverSess.Close()
	})
	startEchoPeer(t, serverSess)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	bridge := NewBridge(clientSess, ln)
	go func() { _ = bridge.Serve() }()
	t.Cleanup(func() { _ = bridge.Close() })

	// Each client connection maps to its own muxado stream; payloads must
	// stay separated.
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func(n int) {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				done <- err
				return
			}
			defer conn.Close() // #nosec G307 -- test cleanup
			msg := string(rune('A' + n))
			if _, err := io.WriteString(conn, msg); err != nil {
				done <- err
				return
			}
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			want := "peer:" + msg + "\n"
			if line != want {
				t.Errorf("client %d: got %q, want %q", n, line, want)
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 4; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("concurrent client failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for concurrent clients")
		}
	}
}

func TestDefaultBridgeAddr(t *testing.T) {
	// 18081 = 8080 + 10000: deliberately outside the ranges dev servers
	// typically bind (3000..9999), so the sandbox's own services can use
	// 8080 and friends. CONCEPT.md §4.3.
	if DefaultBridgeAddr != "127.0.0.1:18081" {
		t.Fatalf("DefaultBridgeAddr = %q, want loopback 18081 (CONCEPT.md §4.3)", DefaultBridgeAddr)
	}
}
