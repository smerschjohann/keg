package proxy

import (
	"net"
	"testing"
)

func TestMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		domain   string
		patterns []string
		want     Decision
	}{
		{
			name:     "empty whitelist denies everything",
			domain:   "proxy.golang.org",
			patterns: nil,
			want:     Deny,
		},
		{
			name:     "exact match allows",
			domain:   "proxy.golang.org",
			patterns: []string{"proxy.golang.org", "example.com"},
			want:     Allow,
		},
		{
			name:     "exact match is case-insensitive",
			domain:   "Proxy.Golang.ORG",
			patterns: []string{"proxy.golang.org"},
			want:     Allow,
		},
		{
			name:     "trailing dot on domain is ignored",
			domain:   "proxy.golang.org.",
			patterns: []string{"proxy.golang.org"},
			want:     Allow,
		},
		{
			name:     "no match denies",
			domain:   "evil.example.com",
			patterns: []string{"proxy.golang.org"},
			want:     Deny,
		},
		{
			name:     "single-level wildcard matches one label",
			domain:   "proxy.golang.org",
			patterns: []string{"*.golang.org"},
			want:     Allow,
		},
		{
			name:     "wildcard does not match bare suffix domain",
			domain:   "golang.org",
			patterns: []string{"*.golang.org"},
			want:     Deny,
		},
		{
			name:     "wildcard is single-level only",
			domain:   "a.b.golang.org",
			patterns: []string{"*.golang.org"},
			want:     Deny,
		},
		{
			name:     "suffix lookalike does not match wildcard",
			domain:   "evil-golang.org",
			patterns: []string{"*.golang.org"},
			want:     Deny,
		},
		{
			name:     "wildcard matches case-insensitively",
			domain:   "DL.Google.COM",
			patterns: []string{"*.google.com"},
			want:     Allow,
		},
		{
			name:     "longest suffix wins among nested wildcards",
			domain:   "api.sub.example.com",
			patterns: []string{"*.sub.example.com", "*.example.com"},
			want:     Allow,
		},
		{
			name:     "specific wildcard beats broad wildcard deterministically",
			domain:   "x.other.example.com",
			patterns: []string{"*.sub.example.com", "*.other.example.com"},
			want:     Allow,
		},
		{
			name:     "exact beats wildcard at same depth",
			domain:   "proxy.golang.org",
			patterns: []string{"*.golang.org", "proxy.golang.org"},
			want:     Allow,
		},
		{
			name:     "wildcard pattern with empty label is literal and matches nothing",
			domain:   "foo",
			patterns: []string{"*."},
			want:     Deny,
		},
		{
			name:     "wildcard star matches single-level domain",
			domain:   "example.com",
			patterns: []string{"*"},
			want:     Allow,
		},
		{
			name:     "wildcard star matches multi-level domain",
			domain:   "a.b.c.example.com",
			patterns: []string{"*"},
			want:     Allow,
		},
		{
			name:     "wildcard star matches case-insensitively",
			domain:   "WWW.Example.ORG",
			patterns: []string{"*"},
			want:     Allow,
		},
		{
			name:     "wildcard star denies empty domain",
			domain:   "",
			patterns: []string{"*"},
			want:     Deny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Match(tt.domain, tt.patterns); got != tt.want {
				t.Fatalf("Match(%q, %v) = %v, want %v", tt.domain, tt.patterns, got, tt.want)
			}
		})
	}
}

// TestMatch_LongestSuffixIsDeterministic pins that repeated calls return the
// identical decision regardless of map-like iteration effects: matching must
// be a pure function of inputs only.
func TestMatch_LongestSuffixIsDeterministic(t *testing.T) {
	t.Parallel()
	patterns := []string{"*.example.com", "a.example.com", "*.b.example.com"}
	for i := 0; i < 50; i++ {
		if got := Match("a.example.com", patterns); got != Allow {
			t.Fatalf("iteration %d: exact entry lost against wildcards: %v", i, got)
		}
		if got := Match("x.b.example.com", patterns); got != Allow {
			t.Fatalf("iteration %d: deeper suffix not matched: %v", i, got)
		}
		if got := Match("example.com", patterns); got != Deny {
			t.Fatalf("iteration %d: bare suffix domain unexpectedly allowed: %v", i, got)
		}
	}
}

func TestNetworkPolicy_LongestPrefixMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowCIDRs []string
		blockCIDRs []string
		allowAll   bool
		ip         string
		want       bool
	}{
		{
			name:       "empty policy allows everything",
			allowCIDRs: nil,
			blockCIDRs: nil,
			ip:         "192.168.1.1",
			want:       true,
		},
		{
			name:       "allow-all flag overrides block rules",
			allowCIDRs: nil,
			blockCIDRs: []string{"0.0.0.0/0"},
			allowAll:   true,
			ip:         "192.168.1.1",
			want:       true,
		},
		{
			name:       "pure blacklist: matching blocked CIDR is denied",
			allowCIDRs: nil,
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "10.1.2.3",
			want:       false,
		},
		{
			name:       "pure blacklist: non-matching IP is allowed",
			allowCIDRs: nil,
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "192.168.1.1",
			want:       true,
		},
		{
			name:       "pure whitelist: matching allowed CIDR is allowed",
			allowCIDRs: []string{"10.0.0.0/8"},
			blockCIDRs: nil,
			ip:         "10.1.2.3",
			want:       true,
		},
		{
			name:       "pure whitelist: non-matching IP is denied",
			allowCIDRs: []string{"10.0.0.0/8"},
			blockCIDRs: nil,
			ip:         "192.168.1.1",
			want:       false,
		},
		{
			name:       "longest prefix match: more specific allow /24 beats broad block /8",
			allowCIDRs: []string{"10.1.2.0/24"},
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "10.1.2.50",
			want:       true,
		},
		{
			name:       "longest prefix match: block /8 denies IP outside allow /24",
			allowCIDRs: []string{"10.1.2.0/24"},
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "10.2.0.1",
			want:       false,
		},
		{
			name:       "longest prefix match: single IP /32 block beats broad allow /16",
			allowCIDRs: []string{"192.168.0.0/16"},
			blockCIDRs: []string{"192.168.1.50/32"},
			ip:         "192.168.1.50",
			want:       false,
		},
		{
			name:       "longest prefix match: allowed IP in /16 not matching /32 block is allowed",
			allowCIDRs: []string{"192.168.0.0/16"},
			blockCIDRs: []string{"192.168.1.50/32"},
			ip:         "192.168.1.51",
			want:       true,
		},
		{
			name:       "internet allow /0 with internal block /8 and specific allow /24",
			allowCIDRs: []string{"0.0.0.0/0", "10.1.2.0/24"},
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "8.8.8.8",
			want:       true,
		},
		{
			name:       "internet allow /0 with internal block /8: blocked IP in /8 is denied",
			allowCIDRs: []string{"0.0.0.0/0", "10.1.2.0/24"},
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "10.5.0.1",
			want:       false,
		},
		{
			name:       "internet allow /0 with internal block /8: exception in /24 is allowed",
			allowCIDRs: []string{"0.0.0.0/0", "10.1.2.0/24"},
			blockCIDRs: []string{"10.0.0.0/8"},
			ip:         "10.1.2.99",
			want:       true,
		},
		{
			name:       "bare single IP without slash /32 suffix parsed correctly",
			allowCIDRs: nil,
			blockCIDRs: []string{"169.254.169.254"},
			ip:         "169.254.169.254",
			want:       false,
		},
		{
			name:       "tie at identical CIDR: block wins (fail-closed)",
			allowCIDRs: []string{"10.0.0.0/16"},
			blockCIDRs: []string{"10.0.0.0/16"},
			ip:         "10.0.1.1",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy, err := NewNetworkPolicy(tt.allowCIDRs, tt.blockCIDRs, tt.allowAll)
			if err != nil {
				t.Fatalf("NewNetworkPolicy error: %v", err)
			}
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tt.ip)
			}
			if got := policy.Evaluate(ip); got != tt.want {
				t.Errorf("policy.Evaluate(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestNewNetworkPolicy_InvalidCIDRErrors(t *testing.T) {
	t.Parallel()
	invalid := []string{"not-a-cidr", "999.999.999.999/24", "10.0.0.1/99"}
	for _, inv := range invalid {
		if _, err := NewNetworkPolicy([]string{inv}, nil, false); err == nil {
			t.Errorf("NewNetworkPolicy(allow=%q) expected error, got nil", inv)
		}
		if _, err := NewNetworkPolicy(nil, []string{inv}, false); err == nil {
			t.Errorf("NewNetworkPolicy(block=%q) expected error, got nil", inv)
		}
	}
}
