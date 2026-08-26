package orchestrator

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/smerschjohann/keg/internal/egress/proxy"

	"golang.ngrok.com/muxado"
)

// ProxyEnv returns the environment entries enabling egress channel A for
// the sandbox: the bridge marker for the guest entrypoint plus proxy
// variables pointing exclusively at the loopback bridge (CONCEPT.md §4.3).
// An empty whitelist yields an empty map — deny-by-default means no proxy,
// not a proxy with no destinations.
func ProxyEnv(domains []string) map[string]string {
	if len(domains) == 0 {
		return map[string]string{}
	}
	url := "http://" + proxy.DefaultBridgeAddr
	return map[string]string{
		EnvProxyBridge: proxy.DefaultBridgeAddr,
		"HTTP_PROXY":   url,
		"HTTPS_PROXY":  url,
		"http_proxy":   url,
		"https_proxy":  url,
		"NO_PROXY":     "localhost,127.0.0.1",
		"no_proxy":     "localhost,127.0.0.1",
	}
}

// EgressProxyConfig is the host-side policy served on channel A.
type EgressProxyConfig struct {
	// Whitelist of exact domains and "*.suffix" patterns.
	Whitelist []string
	// UpstreamProxy ("host:port") forwards allowed targets through the
	// restrictive corporate proxy; empty dials directly.
	UpstreamProxy string
	// Audit receives "<ERLAUBT|BLOCKIERT> <host>" decision lines; nil
	// writes them to stderr.
	Audit io.Writer
}

// Channel returns the host end of the channel whose guest-side descriptor
// number is given (FDProxy/FDDNS/FDRunner), or nil when out of range.
func (s *Sandbox) Channel(guestFD int) *os.File {
	idx := guestFD - FDProxy // hostEnds are stored in channel order
	if idx < 0 || idx >= len(s.hostEnds) {
		return nil
	}
	return s.hostEnds[idx]
}

// StartEgressProxy serves the whitelist proxy on channel A until the
// sandbox exits (closing the host end terminates Serve). The workload can
// use it immediately after Launch returns.
func (s *Sandbox) StartEgressProxy(cfg EgressProxyConfig) error {
	file := s.Channel(FDProxy)
	if file == nil {
		return fmt.Errorf("egress proxy: channel fd %d not available", FDProxy)
	}
	audit := cfg.Audit
	if audit == nil {
		audit = os.Stderr
	}
	server := proxy.Server{
		Whitelist:     cfg.Whitelist,
		UpstreamProxy: cfg.UpstreamProxy,
		DialTimeout:   0,
		Audit: func(ev proxy.AuditEvent) {
			w := bufio.NewWriter(audit)
			_, _ = fmt.Fprintln(w, proxy.FormatAudit(ev.Allowed, ev.Host))
			_ = w.Flush()
		},
	}
	go func() { _ = proxy.Serve(muxado.Server(file, nil), server) }()
	return nil
}
