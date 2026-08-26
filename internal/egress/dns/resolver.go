// Package dns implements egress channel B: the whitelist-filtering
// resolver (hosts mappings → whitelist → upstream → NXDOMAIN), the
// host-side framed server on the channel session, and the guest-side UDP/TCP
// bridge on loopback. Deny-by-default: unknown names never reach upstream.
package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	miek "github.com/miekg/dns"
)

// DefaultTimeout bounds a single upstream exchange.
const DefaultTimeout = 3 * time.Second

// Resolver answers wire-format DNS queries with CONCEPT.md §4.4 precedence:
//  1. static hosts mappings (exact first, then longest single-level
//     wildcard suffix) — authoritative, may deliberately redirect;
//  2. whitelist match — forwarded verbatim to the upstream resolver;
//  3. anything else — NXDOMAIN (deny-by-default).
type Resolver struct {
	// Hosts maps exact names or "*.suffix" patterns to IPv4 addresses.
	Hosts map[string]string
	// Whitelist of exact domains and "*.suffix" patterns (proxy.Match).
	Whitelist []string
	// Upstream resolver address ("host:port"); required for forwarding.
	Upstream string
	// Timeout bounds the upstream exchange (default 3s).
	Timeout time.Duration
	// OnA, if set, is called with every successfully forwarded query name
	// and its A answers — used by the caller to correlate IPs back to
	// names for tcp_endpoints policy.
	OnA func(name string, ips []net.IP)
	// Audit, if set, receives whitelist decisions (allowed, query name).
	Audit func(allowed bool, name string)
}

// HandleQuery takes one wire-format query and returns the wire-format
// response. Malformed queries yield a FORMERR response, never an error —
// the bridge has nothing better to send.
func (r *Resolver) HandleQuery(query []byte) []byte {
	q := new(miek.Msg)
	if err := q.Unpack(query); err != nil || len(q.Question) == 0 {
		return formerr(query)
	}

	name := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")

	if ip, ok := lookupHosts(r.Hosts, name); ok {
		if r.Audit != nil {
			r.Audit(true, name)
		}
		m := new(miek.Msg)
		m.SetReply(q)
		m.Authoritative = true
		if rr, err := miek.NewRR(miek.Fqdn(name) + " 5 IN A " + ip.String()); err == nil {
			m.Answer = append(m.Answer, rr)
		}
		return mustPack(m, query)
	}

	if !matchZone(name, r.Whitelist) {
		if r.Audit != nil {
			r.Audit(false, name)
		}
		return nxdomain(q, query)
	}

	if r.Audit != nil {
		r.Audit(true, name)
	}

	resp, err := r.forward(q)
	if err != nil {
		return servfail(q, query)
	}
	if r.OnA != nil {
		parsed := new(miek.Msg)
		if err := parsed.Unpack(resp); err == nil {
			var ips []net.IP
			for _, rr := range parsed.Answer {
				if a, ok := rr.(*miek.A); ok {
					ips = append(ips, a.A)
				}
			}
			if len(ips) > 0 {
				r.OnA(name, ips)
			}
		}
	}
	return resp
}

// lookupHosts resolves via hosts mappings: exact entry wins; otherwise the
// longest matching single-level wildcard suffix wins ("*.suf.fix" matches
// exactly one leading label — same semantics as the proxy whitelist).
func lookupHosts(hosts map[string]string, name string) (net.IP, bool) {
	if ipStr, ok := hosts[name]; ok {
		return parseIP(ipStr)
	}
	best := -1
	var bestIP net.IP
	for pattern, ipStr := range hosts {
		suffix, ok := wildcardSuffix(pattern)
		if !ok || len(suffix) <= best {
			continue
		}
		if matchesSingleLevel(name, suffix) {
			ip, ok := parseIP(ipStr)
			if !ok {
				continue
			}
			best = len(suffix)
			bestIP = ip
		}
	}
	if best >= 0 {
		return bestIP, true
	}
	return nil, false
}

// wildcardSuffix mirrors proxy.wildcardSuffix for "*.suffix" host keys.
func wildcardSuffix(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "*.") {
		return "", false
	}
	suffix := pattern[2:]
	if strings.Contains(suffix, "*") {
		return "", false
	}
	return suffix, true
}

// matchesSingleLevel reports whether domain is "<one label>." + suffix.
func matchesSingleLevel(domain, suffix string) bool {
	if !strings.HasSuffix(domain, "."+suffix) {
		return false
	}
	label := domain[:len(domain)-len(suffix)-1]
	return label != "" && !strings.Contains(label, ".")
}

func parseIP(s string) (net.IP, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, true
	}
	return ip, true // IPv6 AAAA-style mapping kept simple: A-only today
}

// matchZone evaluates the whitelist with DNS ZONE semantics: a pattern
// matches the exact name or any name below it ("*.svc.cluster.local" is
// hierarchical, unlike the proxy's single-level SNI wildcard — Kubernetes
// names routinely carry multiple labels before the zone).
func matchZone(name string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(p)
		switch {
		case p == "":
			continue
		case strings.HasPrefix(p, "*."):
			suffix := strings.TrimPrefix(p, "*.")
			if name == suffix || strings.HasSuffix(name, "."+suffix) {
				return true
			}
		default:
			if name == p || strings.HasSuffix(name, "."+p) {
				return true
			}
		}
	}
	return false
}

// forward exchanges the query with the upstream resolver over UDP.
func (r *Resolver) forward(q *miek.Msg) ([]byte, error) {
	if r.Upstream == "" {
		return nil, fmt.Errorf("dns: no upstream configured")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := &miek.Client{Net: "udp", Timeout: timeout}
	addr := r.Upstream
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	resp, _, err := client.Exchange(q, addr)
	if err != nil {
		return nil, fmt.Errorf("dns: upstream %s: %w", addr, err)
	}
	return resp.Pack()
}

// response builders -------------------------------------------------------

func baseReply(queryWire []byte, q *miek.Msg) *miek.Msg {
	m := new(miek.Msg)
	m.SetRcode(q, miek.RcodeNameError)
	m.Id = idOf(queryWire)
	m.RecursionAvailable = true
	return m
}

func nxdomain(q *miek.Msg, queryWire []byte) []byte {
	return mustPack(baseReply(queryWire, q), queryWire)
}

func servfail(q *miek.Msg, queryWire []byte) []byte {
	m := baseReply(queryWire, q)
	m.Rcode = miek.RcodeServerFailure
	return mustPack(m, queryWire)
}

func formerr(queryWire []byte) []byte {
	m := new(miek.Msg)
	if len(queryWire) >= 2 {
		m.Id = idOf(queryWire)
	}
	m.Rcode = miek.RcodeFormatError
	m.Response = true
	return mustPack(m, queryWire)
}

func idOf(wire []byte) uint16 {
	return uint16(wire[0])<<8 | uint16(wire[1])
}

// mustPack packs m; on failure falls back to a minimal SERVFAIL echoing
// the query id so clients never hang.
func mustPack(m *miek.Msg, queryWire []byte) []byte {
	wire, err := m.Pack()
	if err == nil {
		return wire
	}
	fallback := new(miek.Msg)
	fallback.Response = true
	fallback.Rcode = miek.RcodeServerFailure
	if len(queryWire) >= 2 {
		fallback.Id = idOf(queryWire)
	}
	wire, perr := fallback.Pack()
	if perr != nil {
		return []byte{queryWire[0], queryWire[1], 0x82, 0x03} // minimal header, SERVFAIL
	}
	return wire
}
