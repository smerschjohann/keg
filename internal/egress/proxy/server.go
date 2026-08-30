package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.ngrok.com/muxado"
)

// DefaultDialTimeout bounds target and upstream dial attempts.
const DefaultDialTimeout = 10 * time.Second

// Server is the host-side endpoint of egress channel A (CONCEPT.md §4.2).
// It consumes one muxado session (the host end of the proxy socketpair) and
// enforces the domain whitelist on every CONNECT or plain-HTTP request.
// Policy lives here exclusively — the guest bridge is byte-transparent.
type Server struct {
	// SNIDomains holds exact domains and "*.suffix" patterns (see Match).
	SNIDomains []string
	// UpstreamProxy is "host:port" of a restrictive upstream HTTP proxy;
	// empty dials targets directly.
	UpstreamProxy string
	// DialTimeout bounds dialing the target/upstream (default 10s).
	DialTimeout time.Duration
	// Audit, if set, receives every policy decision. It must not log
	// payload data; use FormatAudit for the user-visible line format.
	Audit func(AuditEvent)
	// Dial, if set, replaces net.DialTimeout for target connections
	// (production leaves it nil; integration tests inject fake routing).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// RawTargetCheck, if set, allows IP-literal CONNECT targets that fail
	// the domain whitelist (transparent raw-TCP mode): it receives
	// "ip:port" and decides. Domain names are never routed through it.
	RawTargetCheck func(hostPort string) bool
	// NetworkPolicy evaluates destination IP addresses against allow and
	// block CIDRs (Longest Prefix Match).
	NetworkPolicy *NetworkPolicy
}

// AuditEvent records one whitelist decision.
type AuditEvent struct {
	Allowed bool
	Host    string // requested authority ("host:port")
}

// FormatAudit renders an audit event as the fixed user-visible line
// "<ERLAUBT|BLOCKIERT> <host>" (contract pinned by test).
func FormatAudit(allowed bool, host string) string {
	if allowed {
		return "ERLAUBT " + host
	}
	return "BLOCKIERT " + host
}

// Serve accepts streams from sess until the session closes. Each stream
// carries exactly one proxied request; handlers run concurrently and unwind
// when the client disconnects or the tunneled connection dies.
func Serve(sess muxado.Session, cfg Server) error {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return err
		}
		go handleStream(stream, cfg)
	}
}

// handleStream routes either a CONNECT tunnel or a plain HTTP proxy request.
func handleStream(stream net.Conn, cfg Server) {
	defer func() { _ = stream.Close() }()

	br := bufio.NewReader(stream)
	req, err := http.ReadRequest(br)
	if err != nil {
		return // bad or aborted request: drop silently
	}

	if req.Method == http.MethodConnect {
		handleCONNECT(stream, req, cfg)
		return
	}
	handleHTTP(stream, req, cfg)
}

func handleCONNECT(stream net.Conn, req *http.Request, cfg Server) {
	target := req.RequestURI
	if !decide(cfg, target) {
		writeSimpleStatus(stream, http.StatusForbidden, "keg proxy: domain or IP not whitelisted")
		return
	}

	out, err := dialTarget(stream, target, cfg)
	if err != nil {
		writeSimpleStatus(stream, http.StatusBadGateway,
			fmt.Sprintf("keg proxy: cannot connect to %s: %v", target, err))
		return
	}
	defer func() { _ = out.Close() }()

	if _, err := io.WriteString(stream, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tunnel(stream, out)
}

func handleHTTP(stream net.Conn, req *http.Request, cfg Server) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		writeSimpleStatus(stream, http.StatusBadRequest, "keg proxy: missing Host header")
		return
	}
	if !decide(cfg, host) {
		writeSimpleStatus(stream, http.StatusForbidden, "keg proxy: domain or IP not whitelisted")
		return
	}

	timeout := cfg.dialTimeout()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTarget(stream, addr, cfg)
		},
		ResponseHeaderTimeout: timeout,
	}
	// ReadRequest produces server-shaped requests; reshape minimally for
	// transport-level forwarding.
	out := req.Clone(context.Background())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = host
	resp, err := transport.RoundTrip(out)
	if err != nil {
		writeSimpleStatus(stream, http.StatusBadGateway,
			fmt.Sprintf("keg proxy: cannot forward request to %s: %v", host, err))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_ = resp.Write(stream) // verbatim relay incl. body
}

// decide evaluates the whitelist and emits the audit event.
func decide(cfg Server, hostPort string) bool {
	hostOnly := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		hostOnly = h
	}
	allowed := Match(hostOnly, cfg.SNIDomains) == Allow
	if !allowed && cfg.RawTargetCheck != nil {
		if ip := net.ParseIP(hostOnly); ip != nil {
			allowed = cfg.RawTargetCheck(hostPort)
		}
	}
	if allowed && cfg.NetworkPolicy != nil {
		if ip := net.ParseIP(hostOnly); ip != nil {
			allowed = cfg.NetworkPolicy.Evaluate(ip)
		}
	}
	if cfg.Audit != nil {
		cfg.Audit(AuditEvent{Allowed: allowed, Host: hostPort})
	}
	return allowed
}

// dialTarget connects to target either via the configured upstream CONNECT
// proxy or directly.
func dialTarget(_ net.Conn, target string, cfg Server) (net.Conn, error) {
	timeout := cfg.dialTimeout()
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}

	dialTargetAddr := target
	if cfg.NetworkPolicy != nil {
		hostOnly := target
		portOnly := "80"
		if h, p, err := net.SplitHostPort(target); err == nil {
			hostOnly = h
			portOnly = p
		}
		if ip := net.ParseIP(hostOnly); ip != nil {
			if !cfg.NetworkPolicy.Evaluate(ip) {
				return nil, fmt.Errorf("target IP %s blocked by network policy", ip)
			}
		} else if cfg.Dial == nil {
			// Hostname resolution with default dialer: evaluate resolved IPs
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostOnly)
			if err == nil && len(ips) > 0 {
				var allowedIP net.IP
				for _, ip := range ips {
					if cfg.NetworkPolicy.Evaluate(ip) {
						allowedIP = ip
						break
					}
				}
				if allowedIP == nil {
					return nil, fmt.Errorf("target %s resolves only to blocked IP(s)", hostOnly)
				}
				if cfg.UpstreamProxy == "" {
					dialTargetAddr = net.JoinHostPort(allowedIP.String(), portOnly)
				}
			}
		}
	}

	if cfg.UpstreamProxy == "" {
		return dial(context.Background(), "tcp", dialTargetAddr)
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(context.Background(), "tcp", cfg.UpstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", cfg.UpstreamProxy, err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT to upstream: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream CONNECT response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream refused CONNECT with %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// tunnel copies bidirectionally. Whichever direction finishes first
// closes BOTH ends so the other Copy unblocks immediately — no half-dead
// tunnels, no leaked goroutines. (TCP half-close sequencing is sacrificed;
// HTTP proxying never needs it before the peer responds.)
func tunnel(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeBoth() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeBoth() }()
	wg.Wait()
}

func writeSimpleStatus(w io.Writer, code int, message string) {
	statusText := http.StatusText(code)
	body := message + "\n"
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, statusText, len(body), body)
}

func (cfg Server) dialTimeout() time.Duration {
	if cfg.DialTimeout > 0 {
		return cfg.DialTimeout
	}
	return DefaultDialTimeout
}
