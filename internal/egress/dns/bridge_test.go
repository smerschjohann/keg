package dns

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/frame"

	miek "github.com/miekg/dns"

	"golang.ngrok.com/muxado"
)

// rawSocketpair returns an AF_UNIX SOCK_STREAM pair as read-write-closers.
func rawSocketpair(t *testing.T) (io.ReadWriteCloser, io.ReadWriteCloser) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
}

// socketpairSessions wires two muxado sessions over a real socketpair.
func socketpairSessions(t *testing.T) (client, server muxado.Session) {
	t.Helper()
	a, b := rawSocketpair(t)
	client = muxado.Client(a, nil)
	server = muxado.Server(b, nil)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

var testResolver = &Resolver{Hosts: map[string]string{"db.local.test": "127.0.0.1"}}

// hostSide answers framed queries on every accepted stream — the far end
// of the channel (host-side server stand-in).
func hostSide(sess muxado.Session, r *Resolver) {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go func(s net.Conn) {
			defer s.Close() // #nosec G307 -- best-effort close in test peer
			query, err := frame.ReadFrame(s)
			if err != nil {
				return
			}
			resp := r.HandleQuery(query)
			if err := frame.WriteFrame(s, resp); err != nil {
				return
			}
		}(stream)
	}
}

func mustQueryWire(t *testing.T, name string) []byte {
	t.Helper()
	m := new(miek.Msg)
	m.SetQuestion(miek.Fqdn(name), miek.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestServe_AnswersFramedQueries(t *testing.T) {
	t.Parallel()
	clientSess, serverSess := socketpairSessions(t)
	go hostSide(serverSess, testResolver)

	done := make(chan error, 1)
	go func() { done <- Serve(clientSess, testResolver) }()
	defer func() {
		_ = clientSess.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Serve did not return after session close")
		}
	}()

	stream, err := clientSess.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() // #nosec G307 -- test cleanup
	if err := frame.WriteFrame(stream, mustQueryWire(t, "db.local.test")); err != nil {
		t.Fatal(err)
	}
	respWire, err := frame.ReadFrame(stream)
	if err != nil {
		t.Fatal(err)
	}
	resp := new(miek.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != miek.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("served response wrong: rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
}

// ---- bridge -------------------------------------------------------------

// newTestBridge wires a bridge against a host-side peer and returns it plus
// its UDP local address.
func newTestBridge(t *testing.T) (*Bridge, *net.UDPAddr) {
	t.Helper()
	guestEnd, hostEnd := rawSocketpair(t)
	hostSess := muxado.Server(hostEnd, nil)
	go hostSide(hostSess, testResolver)
	clientSess := muxado.Client(guestEnd, nil)
	t.Cleanup(func() {
		_ = clientSess.Close()
		_ = hostSess.Close()
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	udpConn := pc.(*net.UDPConn)
	t.Cleanup(func() { _ = pc.Close() })

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	bridge := NewBridge(clientSess, udpConn, tcpLn)
	go func() { _ = bridge.Serve() }()
	t.Cleanup(func() { _ = bridge.Close() })
	return bridge, udpConn.LocalAddr().(*net.UDPAddr)
}

func TestBridge_UDPRoundtrip(t *testing.T) {
	t.Parallel()
	_, addr := newTestBridge(t)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() // #nosec G307 -- test cleanup
	query := mustQueryWire(t, "db.local.test")
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	resp := new(miek.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != miek.RcodeSuccess || !bytes.Contains(buf[:n], []byte{127, 0, 0, 1}) {
		t.Fatalf("udp answer wrong: rcode=%d wire[12:]=% x", resp.Rcode, buf[12:n])
	}
}

func TestBridge_TCPRoundtrip(t *testing.T) {
	t.Parallel()
	bridge, _ := newTestBridge(t)

	conn, err := net.Dial("tcp", bridge.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() // #nosec G307 -- test cleanup
	if err := frame.WriteFrame(conn, mustQueryWire(t, "denied.example.net")); err != nil {
		t.Fatal(err)
	}
	respWire, err := frame.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	resp := new(miek.Msg)
	if err := resp.Unpack(respWire); err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != miek.RcodeNameError {
		t.Fatalf("tcp deny wrong: rcode=%d, want NXDOMAIN", resp.Rcode)
	}
}

// TestBridge_UDPLoad100 pins the queue-don't-drop requirement (CONCEPT.md
// §4.4): 100 concurrent queries must all be answered.
func TestBridge_UDPLoad100(t *testing.T) {
	t.Parallel()
	_, addr := newTestBridge(t)

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close() // #nosec G307 -- test cleanup
			if _, err := conn.Write(mustQueryWire(t, "db.local.test")); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, 512)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("parallel query failed: %v", err)
	}
}
