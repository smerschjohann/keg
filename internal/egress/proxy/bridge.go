package proxy

import (
	"fmt"
	"net"
	"sync"

	"golang.ngrok.com/muxado"
)

// DefaultBridgeAddr is the loopback address the guest-side proxy bridge
// listens on inside the sandbox (CONCEPT.md §4.3).
const DefaultBridgeAddr = "127.0.0.1:8080"

// Bridge is the guest-side endpoint of egress channel A. It accepts plain
// TCP connections on a loopback listener and pipes every connection
// byte-transparently into one muxado stream of sess. No parsing, no policy
// — the host-side Server decides everything.
type Bridge struct {
	sess muxado.Session
	ln   net.Listener
	wg   sync.WaitGroup
}

// NewBridge wraps an accepted loopback listener and the channel session.
func NewBridge(sess muxado.Session, ln net.Listener) *Bridge {
	return &Bridge{sess: sess, ln: ln}
}

// Serve runs the accept loop until Close is called or the session dies.
func (b *Bridge) Serve() error {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			return fmt.Errorf("proxy bridge: accept: %w", err)
		}
		b.wg.Add(1)
		go func(c net.Conn) {
			defer b.wg.Done()
			defer func() { _ = c.Close() }()
			stream, err := b.sess.Open()
			if err != nil {
				return // session dead: drop the client connection
			}
			defer func() { _ = stream.Close() }()
			tunnel(c, stream)
		}(conn)
	}
}

// Close stops the listener and waits for in-flight pipes to unwind.
func (b *Bridge) Close() error {
	err := b.ln.Close()
	b.wg.Wait()
	return err
}
