package orchestrator

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.ngrok.com/muxado"
)

// Transparent mode: the workload ignores HTTP_PROXY, so the stage builds a
// minimal "real" network (default route via dummy0) and forces every TCP
// connection through a local SNI-splicing relay via nftables REDIRECT.
// Policy stays host-side: the relay synthesizes an HTTP CONNECT carrying the
// SNI hostname over the fd3 channel — Proxy.Serve decides, audits and
// tunnels exactly as in explicit-proxy mode.

const transparentListenAddr = "127.0.0.1:7443"

// setupTransparentNet installs dummy route + nftables ruleset. Requires the
// stage's capabilities (runs before dropCapabilities).
func setupTransparentNet(ports []int) error {
	run := func(name string, args ...string) error {
		cmd := exec.CommandContext(context.Background(), name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
		}
		return nil
	}
	for _, step := range [][]string{
		// A default route via lo is enough: it makes connect() succeed up
		// to the OUTPUT redirect; no packets ever leave the namespace.
		{"ip", "route", "replace", "default", "dev", "lo"},
	} {
		if err := run(step[0], step[1:]...); err != nil {
			return fmt.Errorf("setup: %w", err)
		}
	}
	rulesetFile, err := os.CreateTemp("", "keg-nft-")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	defer func() { _ = os.Remove(rulesetFile.Name()) }()
	if _, err := io.Copy(rulesetFile, rulesetReader(ports)); err != nil {
		_ = rulesetFile.Close()
		return fmt.Errorf("write ruleset: %w", err)
	}
	if err := rulesetFile.Close(); err != nil {
		return fmt.Errorf("close ruleset: %w", err)
	}
	if out, err := exec.CommandContext(context.Background(), "nft", "-f", rulesetFile.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("nft ruleset: %w: %s", err, out)
	}
	return nil
}

func rulesetReader(ports []int) io.Reader {
	var b strings.Builder
	b.WriteString(`table ip keg {
  chain natout {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    udp dport 53 redirect to :53`)
	for _, port := range ports {
		fmt.Fprintf(&b, "\n    tcp dport %d redirect to :7443", port)
	}
	if !containsInt(ports, 443) {
		b.WriteString("\n    tcp dport 443 redirect to :7443")
	}
	b.WriteString(`
  }
  chain enforce {
    type filter hook output priority 10; policy accept;
    ip daddr 127.0.0.0/8 accept
    udp dport 443 drop
    drop
  }
}
`)
	return strings.NewReader(b.String())
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// sniffTimeout bounds the wait for the first peer bytes. Regular clients
// send immediately; the timeout only lets server-first raw protocols
// (peer waits for us) proceed instead of deadlocking the peek.
const sniffTimeout = 2 * time.Second

func startTransparentRelay(file *os.File) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", transparentListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", transparentListenAddr, err)
	}
	sess := muxado.Client(file, nil)
	go func() { _ = serveTransparent(ln, sess, originalDest) }()
	return nil
}

// serveTransparent accepts redirected connections and dispatches them:
// TLS ClientHellos are spliced by SNI hostname (name policy), every other
// stream is passed through as raw TCP to its pre-NAT destination
// (IP/port policy via the DNS correlation table). Both decisions happen
// host-side over the channel; the stage itself holds no policy. origDst
// recovers the pre-NAT destination and is injected for tests (no conntrack
// outside a real redirect environment).
func serveTransparent(ln net.Listener, sess muxado.Session, origDst func(net.Conn) (net.IP, int, bool)) error {
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return aerr // stage shutdown: listener closed
		}
		go handleTransparent(conn, sess, origDst)
	}
}

func handleTransparent(conn net.Conn, sess muxado.Session, origDst func(net.Conn) (net.IP, int, bool)) {
	defer func() { _ = conn.Close() }() // relay connection lifecycle

	dstIP, dstPort, hasDst := origDst(conn)

	buf := make([]byte, 16384)
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	n, rerr := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if n == 0 {
		return // EOF or sniff timeout with no data: nothing to route
	}

	if buf[0] == 0x16 {
		// TLS: accumulate until the ClientHello parses. Anything else —
		// including future ECH hellos without cleartext SNI — is closed
		// (fail-closed); never falls through to the raw path.
		total := n
		for {
			if sni, ok := ParseSNI(buf[:total]); ok {
				port := 443
				if hasDst {
					port = dstPort
				}
				relayCONNECT(conn, sess, sni, port, buf[:total])
				return
			}
			if rerr != nil || total == len(buf) {
				return // no parseable hello within budget: fail-closed
			}
			var n int
			n, rerr = conn.Read(buf[total:])
			total += n
		}
	}

	// Raw TCP passthrough: only with a known pre-NAT destination — the
	// host-side correlation check is meaningless otherwise.
	if !hasDst {
		return
	}
	relayCONNECT(conn, sess, dstIP.String(), dstPort, buf[:n])
}

// relayCONNECT speaks one CONNECT for "host:port" over the channel and then
// splices bytes bidirectionally, replaying prefix (the already-peeked
// payload) after the tunnel opens. Policy (whitelist / correlation) is
// applied host-side before the 200 is ever seen here.
func relayCONNECT(conn net.Conn, sess muxado.Session, host string, port int, prefix []byte) {
	stream, err := sess.Open()
	if err != nil {
		return
	}
	defer func() { _ = stream.Close() }() // relay stream lifecycle
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	if _, err := io.WriteString(stream, req); err != nil {
		return
	}
	status := make([]byte, 512)
	n, err := stream.Read(status)
	if err != nil || n < 12 || status[9] != '2' { // "HTTP/1.1 2xx"
		return
	}
	if len(prefix) > 0 {
		if _, err := stream.Write(prefix); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, conn); done <- struct{}{} }()
	<-done
}
