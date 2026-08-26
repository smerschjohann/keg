package orchestrator

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

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
func setupTransparentNet() error {
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
	if _, err := rulesetFile.WriteString(ruleset); err != nil {
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

const ruleset = `table ip keg {
  chain natout {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    udp dport 53 redirect to :53
    tcp dport 443 redirect to :7443
  }
  chain enforce {
    type filter hook output priority 10; policy accept;
    ip daddr 127.0.0.0/8 accept
    udp dport 443 drop
    drop
  }
  chain enforce {
    type filter hook output priority 10; policy accept;
    ip daddr 127.0.0.0/8 accept
    udp dport 443 drop
    drop
  }
}
`

func startTransparentRelay(file *os.File) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", transparentListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", transparentListenAddr, err)
	}
	sess := muxado.Client(file, nil)
	go func() { _ = serveTransparent(ln, sess) }()
	return nil
}

// serveTransparent accepts redirected connections, extracts the SNI and
// proxies via CONNECT over the channel; non-TLS or SNI-less connections are
// closed immediately (fail-closed).
func serveTransparent(ln net.Listener, sess muxado.Session) error {
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return aerr // stage shutdown: listener closed
		}
		go handleTransparent(conn, sess)
	}
}

func handleTransparent(conn net.Conn, sess muxado.Session) {
	defer func() { _ = conn.Close() }() // relay connection lifecycle
	buf := make([]byte, 16384)
	total := 0
	for {
		n, err := conn.Read(buf[total:])
		total += n
		if sni, ok := ParseSNI(buf[:total]); ok {
			relayCONNECT(conn, sess, sni, buf[:total])
			return
		}
		if err != nil || total == len(buf) {
			return // no ClientHello within budget: fail-closed
		}
	}
}

// relayCONNECT speaks one CONNECT for the SNI host over the channel and then
// splices bytes bidirectionally.
func relayCONNECT(conn net.Conn, sess muxado.Session, sni string, prefix []byte) {
	stream, err := sess.Open()
	if err != nil {
		return
	}
	defer func() { _ = stream.Close() }() // relay stream lifecycle
	req := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", sni, sni)
	if _, err := stream.Write([]byte(req)); err != nil {
		return
	}
	status := make([]byte, 512)
	n, err := stream.Read(status)
	if err != nil || n < 12 || status[9] != '2' { // "HTTP/1.1 2xx"
		return
	}
	if _, err := stream.Write(prefix); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, conn); done <- struct{}{} }()
	<-done
}
