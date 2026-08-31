package orchestrator

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/egress/dns"
	"github.com/smerschjohann/keg/internal/egress/proxy"
	"github.com/smerschjohann/keg/internal/portsfw"
	"github.com/smerschjohann/keg/internal/runner"

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
	SNIDomains []string
	// NetworkPolicy evaluates destination IP addresses against CIDR rules.
	NetworkPolicy *proxy.NetworkPolicy
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
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	idx := guestFD - FDProxy // hostEnds are stored in channel order
	if idx < 0 || idx >= len(s.hostEnds) {
		return nil
	}
	return s.hostEnds[idx]
}

// StartPortsForward serves the port back-channel (Kanal E, CONCEPT.md §4.9):
// every declared entry gets a TCP listener bound to 127.0.0.1 ONLY — a
// collision on a static port is a clear error, dynamic entries arrive with
// pre-bound listeners (the binding IS the reservation, no steal window).
// Each accepted connection is tunneled over channel E to the sandbox
// loopback target. Resources are released by Sandbox.Close.
func (s *Sandbox) StartPortsForward(ports []portsfw.ResolvedPort) error {
	s.closeMu.Lock()
	if s.closed || s.portsStarted {
		s.closeMu.Unlock()
		return nil
	}
	s.portsStarted = true
	s.closeMu.Unlock()

	file := s.Channel(FDPorts)
	if file == nil {
		if s.IsClosed() {
			return nil
		}
		return fmt.Errorf("ports forward: channel fd %d not available", FDPorts)
	}
	sess := muxado.Server(file, nil)
	for _, p := range ports {
		ln := p.Listener
		if ln == nil {
			hostIP := p.HostIP
			if hostIP == "" {
				hostIP = "127.0.0.1"
			}
			var lc net.ListenConfig
			bound, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(hostIP, strconv.Itoa(p.HostPort)))
			if err != nil {
				s.closeMu.Lock()
				for _, opened := range s.portListeners {
					_ = opened.Close()
				}
				s.portListeners = nil
				s.closeMu.Unlock()
				return fmt.Errorf("ports forward %q: bind %s:%d: %w", p.Name, hostIP, p.HostPort, err)
			}
			ln = bound
		}
		s.closeMu.Lock()
		if s.closed {
			s.closeMu.Unlock()
			_ = ln.Close()
			return nil
		}
		s.portListeners = append(s.portListeners, ln)
		s.closeMu.Unlock()
		go func() { _ = portsfw.Forward(sess, ln, p.Guest) }()
	}
	return nil
}

// StartHostForward serves the host end of channel F (host port forward):
// requests from the guest are accepted, verified against the allowed forward specs,
// and connected to the target host/port on the host network.
func (s *Sandbox) StartHostForward(specs []config.ForwardHostSpec) error {
	s.closeMu.Lock()
	if s.closed || s.hostForwardStarted || len(specs) == 0 {
		s.closeMu.Unlock()
		return nil
	}
	s.hostForwardStarted = true
	s.closeMu.Unlock()

	file := s.Channel(FDHostForward)
	if file == nil {
		if s.IsClosed() {
			return nil
		}
		return fmt.Errorf("host forward: channel fd %d not available", FDHostForward)
	}
	sess := muxado.Server(file, nil)
	go func() {
		_ = portsfw.ServeHostForwarder(context.Background(), sess, specs, nil)
	}()
	return nil
}

// StartEgressProxy serves the whitelist proxy on channel A until the
// sandbox exits (closing the host end terminates Serve). The workload can
// use it immediately after Launch returns.
func (s *Sandbox) StartEgressProxy(cfg EgressProxyConfig) error {
	s.closeMu.Lock()
	if cfg.Audit != nil {
		s.proxyAudit = cfg.Audit
	}
	if s.closed || s.proxyStarted {
		s.closeMu.Unlock()
		return nil
	}
	s.proxyStarted = true
	s.closeMu.Unlock()

	file := s.Channel(FDProxy)
	if file == nil {
		if s.IsClosed() {
			return nil
		}
		return fmt.Errorf("egress proxy: channel fd %d not available", FDProxy)
	}
	server := proxy.Server{
		SNIDomains:    cfg.SNIDomains,
		NetworkPolicy: cfg.NetworkPolicy,
		UpstreamProxy: cfg.UpstreamProxy,
		DialTimeout:   0,
		RawTargetCheck: func(hostPort string) bool {
			s.closeMu.Lock()
			raw := s.raw
			s.closeMu.Unlock()
			return raw != nil && raw.check(hostPort)
		},
		ResolveRawHost: func(ip string) string {
			s.closeMu.Lock()
			raw := s.raw
			s.closeMu.Unlock()
			if raw == nil {
				return ""
			}
			return raw.resolveHost(ip)
		},
		Audit: func(ev proxy.AuditEvent) {
			s.closeMu.Lock()
			audit := s.proxyAudit
			s.closeMu.Unlock()
			if audit != nil {
				w := bufio.NewWriter(audit)
				_, _ = fmt.Fprintln(w, proxy.FormatAudit(ev.Allowed, ev.Host))
				_ = w.Flush()
			}
			slog.Info("egress proxy decision", "allowed", ev.Allowed, "host", ev.Host)
		},
	}
	go func() { _ = proxy.Serve(muxado.Server(file, nil), server) }()
	return nil
}

// StartEgressDNS serves the filtering resolver on channel B until the
// sandbox exits. The :53 listener lives in the netns stage; this host side
// applies policy and reaches the upstream with real network access.
func (s *Sandbox) StartEgressDNS(cfg DNSConfig, endpoints []config.TCPEndpoint) error {
	s.closeMu.Lock()
	if cfg.Audit != nil {
		s.dnsAudit = cfg.Audit
	}
	if s.closed || s.dnsStarted {
		s.closeMu.Unlock()
		return nil
	}
	s.dnsStarted = true
	s.closeMu.Unlock()

	file := s.Channel(FDDNS)
	if file == nil {
		if s.IsClosed() {
			return nil
		}
		return fmt.Errorf("egress dns: channel fd %d not available", FDDNS)
	}
	table := newRawEndpoints()
	s.closeMu.Lock()
	s.raw = table
	s.rawCfg = rawCfg{DNSConfig: cfg, Endpoints: endpoints}
	s.closeMu.Unlock()
	resolver := &dns.Resolver{
		Hosts:         cfg.Hosts,
		Whitelist:     cfg.Whitelist,
		NetworkPolicy: cfg.NetworkPolicy,
		Upstream:      cfg.Upstream,
		Audit: func(allowed bool, name string) {
			s.closeMu.Lock()
			audit := s.dnsAudit
			s.closeMu.Unlock()
			if audit != nil {
				w := bufio.NewWriter(audit)
				verdict := "ERLAUBT"
				if !allowed {
					verdict = "BLOCKIERT"
				}
				_, _ = fmt.Fprintf(w, "DNS %s %s\n", verdict, name)
				_ = w.Flush()
			}
			slog.Info("egress dns decision", "allowed", allowed, "name", name)
		},
		OnA: func(name string, ips []net.IP) {
			s.closeMu.Lock()
			eps := s.rawCfg.Endpoints
			s.closeMu.Unlock()
			for _, ep := range eps {
				if name == strings.ToLower(ep.Host) || strings.HasSuffix(name, "."+strings.ToLower(ep.Host)) {
					table.allow(ep.Host, ips, ep.Ports, DefaultRawCorrelationTTL)
				}
			}
		},
	}
	go func() { _ = dns.Serve(muxado.Server(file, nil), resolver) }()
	return nil
}

// StartRunner serves the delegation daemon on channel C until the sandbox
// exits (Sandbox.Close ends the session, which ends ServeSession and kills
// all running jobs). The engine was validated before Launch; whitelisted
// jobs run in the repo root with the host user's environment.
func (s *Sandbox) StartRunner(cfg runner.ServerConfig) error {
	s.closeMu.Lock()
	if cfg.Audit != nil {
		s.runnerAudit = cfg.Audit
	}
	if s.closed || s.runnerStarted {
		s.closeMu.Unlock()
		return nil
	}
	s.runnerStarted = true
	s.closeMu.Unlock()

	file := s.Channel(FDRunner)
	if file == nil {
		if s.IsClosed() {
			return nil
		}
		return fmt.Errorf("runner: channel fd %d not available", FDRunner)
	}
	origAudit := cfg.Audit
	cfg.Audit = func(allowed bool, task string, reason string) {
		s.closeMu.Lock()
		audit := s.runnerAudit
		s.closeMu.Unlock()
		if audit != nil {
			audit(allowed, task, reason)
		} else if origAudit != nil {
			origAudit(allowed, task, reason)
		}
		slog.Info("delegation decision", "allowed", allowed, "task", task, "reason", reason)
	}
	go func() { _ = runner.ServeSession(muxado.Server(file, nil), cfg) }()
	return nil
}
