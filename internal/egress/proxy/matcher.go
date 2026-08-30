// Package proxy implements egress channel A: the domain-whitelist matcher,
// the host-side CONNECT proxy behind the sandbox socketpair, and the
// guest-side bridge that exposes it on loopback inside the sandbox.
// Policy lives entirely on the host side; the bridge is byte-transparent.
package proxy

import (
	"fmt"
	"net"
	"strings"
)

// Decision is the result of a whitelist evaluation.
type Decision int

// Whitelist outcomes. Deny-by-default: an absent or empty whitelist denies.
const (
	Deny Decision = iota
	Allow
)

// Match evaluates domain against the whitelist patterns. Patterns are
// either exact domains ("proxy.golang.org"), single-level wildcards
// ("*.golang.org"), or "*" (allowing any domain). Matching is case-insensitive,
// ignores a trailing dot on the queried domain, and is deterministic:
//
//   - "*" allows all non-empty domains;
//   - an exact pattern wins over any wildcard;
//   - among wildcards the longest matching suffix wins;
//   - "*.suf.fix" matches exactly one leading label: "x.suf.fix" yes,
//     "a.b.suf.fix" no, "suf.fix" no, "evil-suf.fix" no.
func Match(domain string, patterns []string) Decision {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return Deny
	}
	best := -1 // length of longest matched wildcard suffix; exact short-circuits
	for _, p := range patterns {
		pat := strings.ToLower(p)
		if pat == "" {
			continue
		}
		if pat == "*" {
			return Allow
		}
		if !strings.Contains(pat, "*") {
			if pat == domain {
				return Allow // exact always wins
			}
			continue
		}
		suffix, ok := wildcardSuffix(pat)
		if !ok || len(suffix) <= best {
			continue
		}
		if matchesSingleLevel(domain, suffix) {
			best = len(suffix)
		}
	}
	if best >= 0 {
		return Allow
	}
	return Deny
}

// wildcardSuffix strips a single leading "*." and rejects anything else
// that contains a '*' (mid-pattern wildcards are not supported).
func wildcardSuffix(pattern string) (suffix string, ok bool) {
	if !strings.HasPrefix(pattern, "*.") {
		return "", false
	}
	suffix = pattern[2:]
	if strings.Contains(suffix, "*") {
		return "", false
	}
	return suffix, true
}

// matchesSingleLevel reports whether domain is "<one label>." + suffix.
// The separator before the label must be a real dot so lookalike domains
// ("evil-golang.org" vs "*.golang.org") never match.
func matchesSingleLevel(domain, suffix string) bool {
	if !strings.HasSuffix(domain, "."+suffix) {
		return false
	}
	label := domain[:len(domain)-len(suffix)-1]
	return label != "" && !strings.Contains(label, ".")
}

// NetworkAction represents an allow or block decision for a CIDR rule.
type NetworkAction int

const (
	// ActionNone indicates no rule matched.
	ActionNone NetworkAction = iota
	// ActionAllow permits the IP address.
	ActionAllow
	// ActionBlock denies the IP address.
	ActionBlock
)

// CIDRRule pairs an IPNet with its intended action and bit length.
type CIDRRule struct {
	Net    *net.IPNet
	Action NetworkAction
	Bits   int
}

// NetworkPolicy evaluates destination IP addresses against a set of allow and
// block CIDR rules using Longest Prefix Match (most specific subnet wins).
type NetworkPolicy struct {
	rules            []CIDRRule
	hasExplicitAllow bool
	allowAll         bool
}

// NewNetworkPolicy builds a NetworkPolicy from allow and block CIDR strings.
// Bare IPs (e.g. "192.168.1.1") are normalized to single-host CIDRs (/32 or /128).
func NewNetworkPolicy(allowCIDRs, blockCIDRs []string, allowAll bool) (*NetworkPolicy, error) {
	if allowAll {
		return &NetworkPolicy{allowAll: true}, nil
	}
	var rules []CIDRRule
	hasExplicitAllow := false
	for _, raw := range allowCIDRs {
		ipNet, err := parseCIDRorIP(raw)
		if err != nil {
			return nil, fmt.Errorf("allow network: %w", err)
		}
		if ipNet == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		rules = append(rules, CIDRRule{Net: ipNet, Action: ActionAllow, Bits: ones})
		hasExplicitAllow = true
	}
	for _, raw := range blockCIDRs {
		ipNet, err := parseCIDRorIP(raw)
		if err != nil {
			return nil, fmt.Errorf("block network: %w", err)
		}
		if ipNet == nil {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		rules = append(rules, CIDRRule{Net: ipNet, Action: ActionBlock, Bits: ones})
	}
	return &NetworkPolicy{
		rules:            rules,
		hasExplicitAllow: hasExplicitAllow,
		allowAll:         allowAll,
	}, nil
}

// Evaluate checks whether ip is permitted under the policy rules.
// Semantics:
//   - If allowAll is true or no rules are configured, returns true.
//   - When rules match, the most specific subnet (highest bit length) wins.
//   - In case of a tie between Allow and Block at the exact same subnet length, Block wins (fail-closed).
//   - If no rule matches: returns false if explicit allow rules were configured (whitelist mode);
//     otherwise returns true (blacklist-only mode).
func (p *NetworkPolicy) Evaluate(ip net.IP) bool {
	if p == nil || p.allowAll || len(p.rules) == 0 || ip == nil {
		return true
	}
	bestBits := -1
	bestAction := ActionNone
	for _, rule := range p.rules {
		if rule.Net.Contains(ip) {
			if rule.Bits > bestBits {
				bestBits = rule.Bits
				bestAction = rule.Action
			} else if rule.Bits == bestBits && rule.Action == ActionBlock {
				bestAction = ActionBlock // Tie-breaker: fail-closed
			}
		}
	}
	if bestBits >= 0 {
		return bestAction == ActionAllow
	}
	// No rule matched:
	return !p.hasExplicitAllow
}

func parseCIDRorIP(raw string) (*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "/") {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", raw)
		}
		if ip.To4() != nil {
			raw += "/32"
		} else {
			raw += "/128"
		}
	}
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	return ipNet, nil
}
