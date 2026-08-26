package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/smerschjohann/keg/internal/frame"

	"golang.ngrok.com/muxado"
)

// Serve is the host-side endpoint of egress channel B: it accepts muxado
// streams, reads one framed query per stream and answers with one framed
// response. Serve returns when the session dies; per-stream goroutines
// unwind with their streams.
func Serve(sess muxado.Session, r *Resolver) error {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return fmt.Errorf("dns serve: accept: %w", err)
		}
		go func(s net.Conn) {
			defer func() { _ = s.Close() }() // one query/response per stream
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

// Bridge is the guest-side endpoint of channel B (CONCEPT.md §4.4). It
// exposes the resolver on loopback via UDP *and* TCP port 53, framing every
// query onto its own stream of the channel session. Queries are queued as
// concurrent streams — never dropped (backpressure note §4.4).
type Bridge struct {
	sess muxado.Session
	udp  *net.UDPConn
	tcp  net.Listener
	wg   sync.WaitGroup

	closeOnce sync.Once
	closed    chan struct{}
}

// NewBridge wires the channel session to already-bound loopback sockets.
// Both listeners must exist (CONCEPT.md requires UDP and TCP).
func NewBridge(sess muxado.Session, udp *net.UDPConn, tcp net.Listener) *Bridge {
	return &Bridge{
		sess:   sess,
		udp:    udp,
		tcp:    tcp,
		closed: make(chan struct{}),
	}
}

// TCPAddr exposes the TCP listener address (tests use ephemeral ports).
func (b *Bridge) TCPAddr() net.Addr { return b.tcp.Addr() }

// Serve runs both accept loops until Close or session death.
func (b *Bridge) Serve() error {
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	go func() { defer wg.Done(); errCh <- b.serveUDP() }()
	go func() { defer wg.Done(); errCh <- b.serveTCP() }()
	wg.Wait()
	<-errCh // first error wins; second is a duplicate teardown signal
	select {
	case err := <-errCh:
		if isClosed(err) {
			return nil
		}
		return err
	default:
		return nil
	}
}

// Close stops all listeners and waits for in-flight exchanges.
func (b *Bridge) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	var errs []error
	if b.udp != nil {
		if err := b.udp.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if b.tcp != nil {
		if err := b.tcp.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	b.wg.Wait()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (b *Bridge) serveUDP() error {
	buf := make([]byte, frame.MaxSize)
	for {
		n, addr, err := b.udp.ReadFromUDP(buf)
		if err != nil {
			if isClosed(err) || isStopped(b) {
				return nil
			}
			return fmt.Errorf("dns bridge: read udp: %w", err)
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		b.wg.Add(1)
		go func(a *net.UDPAddr, q []byte) {
			defer b.wg.Done()
			resp := b.exchange(q)
			if resp == nil {
				return
			}
			if _, err := b.udp.WriteToUDP(resp, a); err != nil && !isStopped(b) {
				// best effort: client retries per DNS semantics
				_ = err
			}
		}(addr, query)
	}
}

func (b *Bridge) serveTCP() error {
	for {
		conn, err := b.tcp.Accept()
		if err != nil {
			if isClosed(err) || isStopped(b) {
				return nil
			}
			return fmt.Errorf("dns bridge: accept tcp: %w", err)
		}
		b.wg.Add(1)
		go func(c net.Conn) {
			defer b.wg.Done()
			defer func() { _ = c.Close() }() // conn-scoped exchange
			for {
				query, err := frame.ReadFrame(c)
				if err != nil {
					return
				}
				resp := b.exchange(query)
				if resp == nil {
					return
				}
				if err := frame.WriteFrame(c, resp); err != nil {
					return
				}
			}
		}(conn)
	}
}

// exchange sends one framed query over a fresh stream and waits for the
// framed response.
func (b *Bridge) exchange(query []byte) []byte {
	stream, err := b.sess.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = stream.Close() }() // one-shot exchange stream
	if err := frame.WriteFrame(stream, query); err != nil {
		return nil
	}
	resp, err := frame.ReadFrame(stream)
	if err != nil {
		return nil
	}
	return resp
}

// isStopped reports whether Close has been called on this bridge.
func isStopped(b *Bridge) bool {
	select {
	case <-b.closed:
		return true
	default:
		return false
	}
}

// isClosed recognizes listener-closed errors so orderly teardown does not
// surface as an error return.
func isClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "closed")
}
