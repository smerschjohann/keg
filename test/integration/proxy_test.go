//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

const proxyRepoConfig = `
version: "1"
network:
  sni_domains:
    - proxy.golang.org
`

// speakCONNECTViaBridge is a shell snippet that talks to the guest proxy
// bridge on loopback using bash /dev/tcp (no curl dependency): one CONNECT
// request, first response line printed.
const speakCONNECTViaBridge = `
exec 3<>/dev/tcp/127.0.0.1/18081 || exit 97
printf 'CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n' "$TARGET" "$TARGET" >&3
IFS= read -r line <&3
printf '%s\n' "$line"
`

func TestSandboxProxyChannelDenied(t *testing.T) {
	var audit strings.Builder
	dir := t.TempDir()
	out, code := runInSandboxWithConfig(t, dir, proxyRepoConfig, orchestrator.OverlayPlain,
		// Startup slack: Launch hands over after its 750 ms stability
		// window only for surviving processes; a fast-exit workload would
		// legitimately tear the channels down before we can serve them.
		`sleep 2; echo "proxy=$HTTP_PROXY"; TARGET=blocked.example.com `+speakCONNECTViaBridge,
		func(plan *orchestrator.Plan) {
			plan.Command = []string{"/bin/bash", "-c", `sleep 2; echo "proxy=$HTTP_PROXY"; TARGET=blocked.example.com ` + speakCONNECTViaBridge}
			for k, v := range orchestrator.ProxyEnv([]string{"proxy.golang.org"}) {
				plan.EnvSet[k] = v
			}
			plan.SNIDomains = []string{"proxy.golang.org"}
		},
		func(sb *orchestrator.Sandbox) {
			err := sb.StartEgressProxy(orchestrator.EgressProxyConfig{
				SNIDomains: []string{"proxy.golang.org"},
				Audit:      &audit,
			})
			if err != nil {
				t.Fatalf("start egress proxy: %v", err)
			}
		})
	if code != 0 {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if !strings.Contains(out, "proxy=http://127.0.0.1:18081") {
		t.Errorf("HTTP_PROXY not injected as expected, output:\n%s", out)
	}
	if !strings.Contains(out, "403") {
		t.Errorf("expected visible 403 for non-whitelisted domain, output:\n%s", out)
	}
	if !strings.Contains(audit.String(), "BLOCKIERT blocked.example.com:443") {
		t.Errorf("audit log missing deny decision: %q", audit.String())
	}
}

func TestSandboxNoWhitelistNoBridge(t *testing.T) {
	dir := t.TempDir()
	// Without allowed_domains no bridge marker is set; the sandbox must
	// still run (bridge absence must never break workloads).
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `echo env-ok`)
	if code != 0 || !strings.Contains(out, "env-ok") {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if strings.Contains(out, "KEG_PROXY") {
		t.Errorf("bridge marker leaked into workload env: %s", out)
	}
}
