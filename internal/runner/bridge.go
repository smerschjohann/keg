package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"golang.ngrok.com/muxado"
)

// Bridge serves the guest end of delegation channel C: it accepts
// workload connections on the filesystem socket (CONCEPT.md §3:
// /run/keg/runner.sock) and pipes each one byte-transparently onto
// its own muxado stream. Returning stops the bridge; callers cancel ctx.
func Bridge(ctx context.Context, sess muxado.Session, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		// Teardown order per M2/M4 notes: close the transport first so all
		// streams and pending Accepts wake up, then the listener.
		_ = sess.Close()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("runner bridge accept: %w", err)
		}
		stream, serr := sess.Open()
		if serr != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("runner bridge open stream: %w", serr)
		}
		go pump(conn, stream)
	}
}

// pump copies both directions until EOF/error, then closes both ends.
func pump(conn net.Conn, stream io.ReadWriteCloser) {
	defer func() {
		_ = conn.Close()
		_ = stream.Close()
	}()
	done := make(chan struct{}, 2)
	copy := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copy(stream, conn)
	go copy(conn, stream)
	<-done // first finished direction ends the pipe; Close wakes the other
}

// ServeGuestSocket binds SocketPath inside the sandbox and runs Bridge on
// it. The directory is created first (the orchestrator mounts a tmpfs at
// /run only when delegation is configured).
func ServeGuestSocket(ctx context.Context, sess muxado.Session) error {
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o750); err != nil {
		return fmt.Errorf("runner bridge: create socket dir: %w", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", SocketPath)
	if err != nil {
		return fmt.Errorf("runner bridge: bind %s: %w", SocketPath, err)
	}
	return Bridge(ctx, sess, ln)
}
