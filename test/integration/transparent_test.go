//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

const transparentRepoConfig = `
version: "1"
network:
  mode: transparent
  sni_domains:
    - "*.svc.cluster.local"
    - "cluster.local"
`

// TestSandboxTransparentMode proves a proxy-ignoring workload reaches an
// allowed HTTPS endpoint through nftables redirect + SNI policy: curl runs
// WITHOUT proxy env and validates end-to-end TLS against the pod's
// serviceaccount CA (real cluster endpoint, no fakes).
func TestSandboxTransparentMode(t *testing.T) {
	dir := t.TempDir()
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	if _, err := os.Stat(caPath); err != nil {
		t.Skipf("skipping in-cluster transparent mode test: serviceaccount CA not found (%v)", err)
	}
	upstream := hostUpstream(t)
	caData := readFileOrDie(t, caPath)

	script := `
sleep 1
echo "proxy-vars=[$(env | grep -iE '^(https?_proxy|no_proxy)=' | cut -d= -f1 | paste -sd,)]"
curl --cacert /run/ca/ca.crt --max-time 10 -sS https://kubernetes.default.svc.cluster.local/version 2>&1 | head -c 300
if [ ${PIPESTATUS[0]} -eq 0 ]; then echo; echo sni-ok; else echo sni-failed; fi
if curl --cacert /run/ca/ca.crt --max-time 5 -sf https://evil.invalid/version >/dev/null 2>&1; then echo deny-failed; else echo deny-ok; fi
`
	out, code := runInSandboxWithConfig(t, dir, transparentRepoConfig, orchestrator.OverlayPlain,
		script,
		func(plan *orchestrator.Plan) {
			plan.Transparent = true
			plan.ResolvConf = writeTempFile(t, "resolv.conf",
				"nameserver 127.0.0.1\noptions timeout:1 retries:1\n")
			// SNI policy is deliberately single-level (CONCEPT §4.2): the
			// exact endpoint is whitelisted by name, DNS uses zone semantics
			// for cluster-local resolution (M3 note 5).
			dnsZones := []string{"*.svc.cluster.local", "cluster.local"}
			sniExact := []string{"kubernetes.default.svc.cluster.local"}
			plan.SNIDomains = sniExact
			plan.EgressDNS = &orchestrator.DNSConfig{
				Whitelist: append(append([]string{}, dnsZones...), sniExact...),
				Upstream:  upstream,
			}
			_ = caData
			plan.Mounts = append(plan.Mounts, mountFile(caPath, "/run/ca/ca.crt"))
		},
		func(sb *orchestrator.Sandbox) {
			if err := sb.StartEgressDNS(orchestrator.DNSConfig{
				Whitelist: []string{"*.svc.cluster.local", "cluster.local", "kubernetes.default.svc.cluster.local"},
				Upstream:  upstream,
			}, nil); err != nil {
				t.Errorf("egress dns: %v", err)
			}
			if err := sb.StartEgressProxy(orchestrator.EgressProxyConfig{
				SNIDomains: []string{"kubernetes.default.svc.cluster.local"},
			}); err != nil {
				t.Errorf("egress proxy: %v", err)
			}
		})

	if code != 0 {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if !strings.Contains(out, "proxy-vars=[]") {
		t.Errorf("transparent mode must not inject proxy vars, output:\n%s", out)
	}
	if strings.Contains(out, "deny-failed") || !strings.Contains(out, "deny-ok") {
		t.Errorf("non-whitelisted endpoint was reachable, output:\n%s", out)
	}
	if !strings.Contains(out, "sni-ok") || strings.Contains(out, "sni-failed") {
		t.Errorf("SNI-spliced TLS request to whitelisted endpoint failed, output:\n%s", out)
	}
}
