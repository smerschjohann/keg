package orchestrator

import (
	"os"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/egress/proxy"
)

// TestProxyEnv pins the environment contract injected when a repo declares
// an egress whitelist (CONCEPT.md §4.3): bridge marker plus proxy variables
// pointing exclusively at the loopback bridge.
func TestProxyEnv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		domains []string
		wantSet bool
	}{
		{"no whitelist means no proxy env", nil, false},
		{"empty whitelist means no proxy env", []string{}, false},
		{"whitelist enables proxy env", []string{"proxy.golang.org"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := ProxyEnv(tt.domains)
			if !tt.wantSet {
				if len(env) != 0 {
					t.Fatalf("ProxyEnv(%v) = %v, want empty", tt.domains, env)
				}
				return
			}
			url := "http://" + proxy.DefaultBridgeAddr
			want := map[string]string{
				EnvProxyBridge: proxy.DefaultBridgeAddr,
				"HTTP_PROXY":   url,
				"HTTPS_PROXY":  url,
				"http_proxy":   url,
				"https_proxy":  url,
				"NO_PROXY":     "localhost,127.0.0.1",
				"no_proxy":     "localhost,127.0.0.1",
			}
			if len(env) != len(want) {
				t.Fatalf("ProxyEnv keys = %v, want %v", env, want)
			}
			for k, v := range want {
				if env[k] != v {
					t.Errorf("ProxyEnv[%s] = %q, want %q", k, env[k], v)
				}
			}
		})
	}
}

// TestInvariant_ProxyEnvNeverPointsOffLoopback guards THREAT_MODEL §8.1:
// proxy settings inside the sandbox must never direct traffic anywhere but
// the local bridge.
func TestInvariant_ProxyEnvNeverPointsOffLoopback(t *testing.T) {
	t.Parallel()
	for _, v := range ProxyEnv([]string{"anything.example.com"}) {
		switch v {
		case "localhost,127.0.0.1", proxy.DefaultBridgeAddr:
			continue
		}
		if strings.HasPrefix(v, "http://127.0.0.1:") || strings.HasPrefix(v, "http://localhost:") {
			continue
		}
		t.Fatalf("proxy env value escapes loopback: %q", v)
	}
}

// TestSandbox_ChannelAccessor pins the fd contract between launch and the
// egress servers.
func TestSandbox_ChannelAccessor(t *testing.T) {
	f1, err := os.Open("/dev/null") // #nosec G304 -- fixed safe path
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close() // #nosec G307 -- test cleanup
	sb := &Sandbox{hostEnds: []*os.File{f1, nil}}
	if got := sb.Channel(FDProxy); got != f1 {
		t.Errorf("Channel(FDProxy) = %v, want first host end", got)
	}
	if got := sb.Channel(FDDNS); got != nil {
		t.Errorf("Channel(FDDNS) = %v, want nil placeholder", got)
	}
	if got := sb.Channel(99); got != nil {
		t.Errorf("Channel(99) = %v, want nil", got)
	}
}
