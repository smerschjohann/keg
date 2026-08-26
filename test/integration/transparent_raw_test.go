//go:build integration

package integration

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"

	miek "github.com/miekg/dns"
)

const transparentRawRepoConfig = `
version: "1"
network:
  mode: transparent
  tcp_endpoints:
    - host: echo.raw.test
      ports: [%d]
`

// outboundIP returns the pod's own address as seen on the default route:
// host-side wildcard listeners reach it, and it is a non-loopback target
// so the stage's nftables OUTPUT redirect applies to it.
func outboundIP(t *testing.T) string {
	t.Helper()
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Skipf("no routable interface for outbound IP: %v", err)
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	if ip.IsLoopback() {
		t.Skip("only loopback routing available")
	}
	return ip.String()
}

// fakeDNSUpstream serves A answers for exactly one fixed name→IP mapping
// and NXDOMAIN for everything else — a controlled replacement for kube-dns.
func fakeDNSUpstream(t *testing.T, name, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake dns listen: %v", err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			q := new(miek.Msg)
			if q.Unpack(buf[:n]) != nil || len(q.Question) == 0 {
				continue
			}
			m := new(miek.Msg)
			m.SetReply(q)
			if strings.EqualFold(q.Question[0].Name, miek.Fqdn(name)) {
				rr, rerr2 := miek.NewRR(fmt.Sprintf("%s 5 IN A %s", miek.Fqdn(name), ip))
				if rerr2 == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				m.Rcode = miek.RcodeNameError
			}
			out, _ := m.Pack()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// wildcardEchoOrigin listens on all interfaces so dialing <podIP>:<port>
// reaches it from the host-side proxy.
func wildcardEchoOrigin(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("echo origin listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() // #nosec G307 -- best-effort close in test server
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestSandboxRawTCPPassthrough proves the full transparent raw-TCP path
// end to end: the DNS answer feeds the IP correlation table (channel B),
// the workload connects to the resolved IP without any proxy configuration,
// nftables redirects the stream into the relay, SO_ORIGINAL_DST recovers
// the pre-NAT destination and channel A enforces the endpoint+port policy.
func TestSandboxRawTCPPassthrough(t *testing.T) {
	dir := t.TempDir()
	podIP := outboundIP(t)
	dnsAddr := fakeDNSUpstream(t, "echo.raw.test", podIP)
	port := wildcardEchoOrigin(t)

	cfg := fmt.Sprintf(transparentRawRepoConfig, port)
	script := fmt.Sprintf(`
sleep 0.5
ip=$(getent hosts echo.raw.test | awk '{print $1}')
echo "resolved=$ip"
exec 3<>/dev/tcp/$ip/%[1]d || { echo connect-failed; exit 1; }
printf 'hello\n' >&3
line=$(head -c 6 <&3)
echo "got=$line"
# Deny case: same port, but an IP that was never correlated.
reply=$(timeout 5 bash -c 'exec 3<>/dev/tcp/192.0.2.1/%[1]d && printf "x\n" >&3 && head -c 1 <&3' 2>/dev/null)
if [ -n "$reply" ]; then echo deny-failed; else echo deny-ok; fi
`, port)

	dnsCfg := orchestrator.DNSConfig{
		Whitelist: []string{"echo.raw.test"},
		Upstream:  dnsAddr,
	}
	endpoints := []config.TCPEndpoint{{Host: "echo.raw.test", Ports: []int{port}}}

	out, code := runInSandboxWithConfig(t, dir, cfg, orchestrator.OverlayPlain,
		script,
		func(plan *orchestrator.Plan) {
			plan.Transparent = true
			plan.ResolvConf = writeTempFile(t, "resolv.conf",
				"nameserver 127.0.0.1\noptions timeout:1 retries:1\n")
			plan.EgressDNS = &dnsCfg
			plan.TCPEndpoints = endpoints
		},
		func(sb *orchestrator.Sandbox) {
			// Order matters: the correlation table must exist before the
			// proxy captures it.
			if err := sb.StartEgressDNS(dnsCfg, endpoints); err != nil {
				t.Errorf("egress dns: %v", err)
			}
			if err := sb.StartEgressProxy(orchestrator.EgressProxyConfig{}); err != nil {
				t.Errorf("egress proxy: %v", err)
			}
		})

	if code != 0 {
		t.Fatalf("exit=%d output:\n%s", code, out)
	}
	if !strings.Contains(out, fmt.Sprintf("resolved=%s", podIP)) {
		t.Errorf("name not resolved to pod IP via fake upstream, output:\n%s", out)
	}
	if !strings.Contains(out, "got=hello") {
		t.Errorf("raw TCP payload did not round-trip through redirect+relay, output:\n%s", out)
	}
	if !strings.Contains(out, "deny-ok") || strings.Contains(out, "deny-failed") {
		t.Errorf("uncorrelated IP was not denied, output:\n%s", out)
	}
}
