package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.ngrok.com/muxado"
)

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

// pipeSessions wires two muxado sessions over a net.Pipe so protocol tests
// run without bwrap or real sockets between guest and host.
func pipeSessions(t *testing.T) (client, server muxado.Session) {
	t.Helper()
	hostConn, guestConn := net.Pipe()
	client = muxado.Client(guestConn, nil)
	server = muxado.Server(hostConn, nil)
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

func TestServer_CONNECTAllowed(t *testing.T) {
	target := echoServer(t)
	client, server := pipeSessions(t)
	startServer(t, server, Server{
		Whitelist: []string{"*.example.com"},
		Dial:      fakeDial(target),
	})

	resp, stream := speakCONNECT(t, client, "data.example.com:"+portOf(target))
	if !strings.HasPrefix(resp.Status, "200") {
		t.Fatalf("tunnel refused, got status %q", resp.Status)
	}
	// The 200 response body must not hold the bufio buffer we now read
	// from as a raw tunnel.
	_ = resp.Body.Close()
	// Bidirectional payload through the established tunnel.
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, 4)
	if err := stream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("payload corrupted: %q", buf)
	}
}

func TestServer_CONNECTDenied(t *testing.T) {
	var audits []AuditEvent
	client, server := pipeSessions(t)
	startServer(t, server, Server{
		Whitelist:   []string{"proxy.golang.org"},
		DialTimeout: time.Second,
		Audit:       func(e AuditEvent) { audits = append(audits, e) },
	})

	resp, _ := speakCONNECT(t, client, "evil.example.com:443")
	if !strings.HasPrefix(resp.Status, "403") {
		t.Fatalf("expected 403, got %q", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if !strings.Contains(string(body), "not whitelisted") {
		t.Fatalf("deny reason missing from body: %q", body)
	}
	if len(audits) != 1 || audits[0].Allowed || !strings.HasPrefix(audits[0].Host, "evil.example.com") {
		t.Fatalf("audit event wrong: %+v", audits)
	}
}

func TestServer_UpstreamRefusesConnect(t *testing.T) {
	upstream := echoServer(t) // accepts TCP but never answers CONNECT properly
	client, server := pipeSessions(t)
	startServer(t, server, Server{
		Whitelist:     []string{"*.example.com"},
		UpstreamProxy: upstream,
		DialTimeout:   500 * time.Millisecond,
	})

	resp, _ := speakCONNECT(t, client, "data.example.com:443")
	if !strings.HasPrefix(resp.Status, "502") {
		t.Fatalf("expected 502 from failing upstream, got %q", resp.Status)
	}
	_ = resp.Body.Close()
}

func TestServer_PlainHTTPAllowed(t *testing.T) {
	// Fake origin server speaking real HTTP behind the whitelist.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() // #nosec G307 -- best-effort close in test server
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				resp := fmt.Sprintf(
					"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\nhello %s",
					len("hello "+req.Host), req.Host)
				_, _ = io.WriteString(c, resp)
			}(conn)
		}
	}()

	client, server := pipeSessions(t)
	startServer(t, server, Server{
		Whitelist: []string{"web.example.com"},
		Dial:      fakeDial(addr),
	})

	stream := openStream(t, client)
	fmt.Fprintf(stream, "GET /path HTTP/1.1\r\nHost: web.example.com:%s\r\nConnection: close\r\n\r\n", portOf(addr))
	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello web.example.com") {
		t.Fatalf("plain HTTP forwarding broken: %d %q", resp.StatusCode, body)
	}
}

// TestServer_PlainHTTPDenied checks the whitelist on the Host header of
// origin-form requests.
func TestServer_PlainHTTPDenied(t *testing.T) {
	client, server := pipeSessions(t)
	startServer(t, server, Server{Whitelist: []string{"web.example.com"}, DialTimeout: time.Second})

	stream := openStream(t, client)
	fmt.Fprint(stream, "GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// TestServer_GoroutineLeakFree verifies the halboffene Verbindungen case:
// after the session dies, Serve and all per-stream handlers must unwind.
func TestServer_GoroutineLeakFree(t *testing.T) {
	before := runtimeNumGoroutine()
	target := echoServer(t)

	func() {
		client, server := pipeSessions(t)
		startServer(t, server, Server{
			Whitelist: []string{"*.example.com"},
			Dial:      fakeDial(target),
		})
		resp, _ := speakCONNECT(t, client, "data.example.com:"+portOf(target))
		_ = resp.Body.Close()
		if !strings.HasPrefix(resp.Status, "200") {
			t.Fatalf("setup failed: %q", resp.Status)
		}
		// Half-open connection: only the client side closes below via
		// session teardown.
		_ = client.Close()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtimeNumGoroutine() <= before+1 { // small tolerance for runtime internals
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: before=%d after=%d", before, runtimeNumGoroutine())
}

// TestFormatAudit pins the audit line format (user-visible contract).
func TestFormatAudit(t *testing.T) {
	tests := []struct {
		allowed bool
		host    string
		want    string
	}{
		{true, "proxy.golang.org:443", "ERLAUBT proxy.golang.org:443"},
		{false, "evil.example.com:443", "BLOCKIERT evil.example.com:443"},
	}
	for _, tt := range tests {
		if got := FormatAudit(tt.allowed, tt.host); got != tt.want {
			t.Errorf("FormatAudit(%v, %q) = %q, want %q", tt.allowed, tt.host, got, tt.want)
		}
	}
}
