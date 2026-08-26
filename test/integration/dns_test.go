//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

const dnsRepoConfig = `
version: "1"
network:
  allowed_domains:
    - "*.svc.cluster.local"
    - "cluster.local"
`

// hostUpstream returns the host's own resolver (kube-dns in this
// environment): external DNS is unreachable here, cluster names are the
// real-world case keg targets.
func hostUpstream(t *testing.T) string {
	t.Helper()
	// Parse the first nameserver from the host resolv.conf.
	out := readFileOrDie(t, "/etc/resolv.conf")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		}
	}
	t.Skip("no nameserver in host /etc/resolv.conf")
	return ""
}

func TestSandboxDNSChannel(t *testing.T) {
	dir := t.TempDir()
	upstream := hostUpstream(t)

	script := `
sleep 0.5
echo "resolv=$(grep -c 'nameserver 127.0.0.1' /etc/resolv.conf)"
getent hosts kubernetes.default.svc.cluster.local || echo resolve-failed
if getent hosts blocked.invalid >/dev/null 2>&1; then echo deny-failed; else echo deny-ok; fi
`
	out, code := runInSandboxWithConfig(t, dir, dnsRepoConfig, orchestrator.OverlayPlain,
		script,
		func(plan *orchestrator.Plan) {
			for k, v := range orchestrator.ProxyEnv([]string{"*.svc.cluster.local"}) {
				plan.EnvSet[k] = v
			}
			plan.ResolvConf = writeTempFile(t, "resolv.conf",
				"nameserver 127.0.0.1\noptions timeout:1 retries:1\n")
			plan.EgressWhitelist = []string{"*.svc.cluster.local", "cluster.local"}
			plan.EgressDNS = &orchestrator.DNSConfig{
				Whitelist: []string{"*.svc.cluster.local", "cluster.local"},
				Upstream:  upstream,
			}
		},
		func(sb *orchestrator.Sandbox) {
			if err := sb.StartEgressDNS(orchestrator.DNSConfig{
				Whitelist: []string{"*.svc.cluster.local", "cluster.local"},
				Upstream:  upstream,
			}); err != nil {
				t.Errorf("egress dns: %v", err)
			}
		})

	if code != 0 {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if !strings.Contains(out, "resolv=1") {
		t.Errorf("resolv.conf not injected into sandbox, output:\n%s", out)
	}
	if !strings.Contains(out, "10.") || strings.Contains(out, "resolve-failed") {
		t.Errorf("cluster name not resolved via channel B (:53), output:\n%s", out)
	}
	if !strings.Contains(out, "deny-ok") || strings.Contains(out, "deny-failed") {
		t.Errorf("non-whitelisted name was not denied, output:\n%s", out)
	}
}

func readOrSkip() {}
