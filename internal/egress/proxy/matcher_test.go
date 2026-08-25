package proxy

import "testing"

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
