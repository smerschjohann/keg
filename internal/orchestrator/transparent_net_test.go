package orchestrator

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestRulesetReader_RedirectsAndEnforcement(t *testing.T) {
	t.Parallel()
	rules, err := io.ReadAll(rulesetReader([]int{9000, 5432}))
	if err != nil {
		t.Fatal(err)
	}
	got := string(rules)

	musts := []string{
		// DNS is forced into the stage resolver even if the workload
		// hardcodes an external nameserver.
		"udp dport 53 redirect to :53",
		// every configured endpoint port lands in the relay
		"tcp dport 9000 redirect to :7443",
		"tcp dport 5432 redirect to :7443",
		// SNI traffic is redirected even with no tcp_endpoints on 443
		"tcp dport 443 redirect to :7443",
		// loopback (relay, DNS) never leaves
		"ip daddr 127.0.0.0/8",
		// deny-by-default egress enforcement lives in postrouting:
		// replies of already-inspected flows pass, everything else drops
		"ct state established,related accept",
	}
	for _, m := range musts {
		if !strings.Contains(got, m) {
			t.Errorf("ruleset missing %q:\n%s", m, got)
		}
	}

	// 443 must not be redirected twice when configured explicitly.
	if strings.Count(got, "tcp dport 443 redirect") != 1 {
		t.Errorf("port 443 redirect duplicated:\n%s", got)
	}

	// Enforcement MUST NOT be an output-hook filter chain: nftables reroutes
	// redirected packets only after all output hooks, so such a chain sees
	// pre-NAT destinations and kills every flow (empirical finding).
	if strings.Contains(got, "hook output priority 10") {
		t.Errorf("enforcement must not run as output filter chain:\n%s", got)
	}
	if !strings.Contains(got, "hook postrouting") {
		t.Errorf("enforcement must live in postrouting:\n%s", got)
	}
	if !strings.Contains(got, "drop") {
		t.Errorf("deny-by-default drop missing:\n%s", got)
	}
}

func TestOutboundIPv4Sanity(t *testing.T) {
	t.Parallel()
	ip, err := OutboundIPv4()
	if err != nil {
		t.Skipf("no outbound route on this host: %v", err)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.IsUnspecified() || parsed.IsLoopback() {
		t.Fatalf("OutboundIPv4 = %q, want a usable non-loopback IPv4", ip)
	}
}
