// Package proxy implements egress channel A: the domain-whitelist matcher,
// the host-side CONNECT proxy behind the sandbox socketpair, and the
// guest-side bridge that exposes it on loopback inside the sandbox.
// Policy lives entirely on the host side; the bridge is byte-transparent.
package proxy

import "strings"

// Decision is the result of a whitelist evaluation.
type Decision int

// Whitelist outcomes. Deny-by-default: an absent or empty whitelist denies.
const (
	Deny Decision = iota
	Allow
)

// Match evaluates domain against the whitelist patterns. Patterns are
// either exact domains ("proxy.golang.org") or single-level wildcards
// ("*.golang.org"). Matching is case-insensitive, ignores a trailing dot on
// the queried domain, and is deterministic:
//
//   - an exact pattern wins over any wildcard;
//   - among wildcards the longest matching suffix wins;
//   - "*.suf.fix" matches exactly one leading label: "x.suf.fix" yes,
//     "a.b.suf.fix" no, "suf.fix" no, "evil-suf.fix" no.
func Match(domain string, patterns []string) Decision {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	best := -1 // length of longest matched wildcard suffix; exact short-circuits
	for _, p := range patterns {
		pat := strings.ToLower(p)
		if pat == "" {
			continue
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
