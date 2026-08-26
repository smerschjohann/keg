package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/egress/proxy"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

const fixtureRepoYAML = `
version: "1"
env:
  set:
    LOG_FORMAT: json
  unset:
    - AWS_SESSION_TOKEN
network:
  sni_domains:
    - proxy.golang.org
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRunPlan_MissingRepoConfigIsClearError(t *testing.T) {
	dir := t.TempDir()
	_, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil {
		t.Fatal("missing repo config must fail")
	}
	if !strings.Contains(err.Error(), ".keg.yaml") {
		t.Errorf("error must name the expected file: %v", err)
	}
}

func TestBuildRunPlan_Minimal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	wantRoot, _ := filepath.EvalSymlinks(dir)
	if plan.RepoRoot != wantRoot && plan.RepoRoot != filepath.Clean(dir) {
		t.Errorf("RepoRoot = %q, want %q", plan.RepoRoot, wantRoot)
	}
	if plan.EnvSet["LOG_FORMAT"] != "json" {
		t.Errorf("EnvSet = %v, want LOG_FORMAT=json", plan.EnvSet)
	}
	found := false
	for _, v := range plan.EnvUnset {
		if v == "AWS_SESSION_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Errorf("EnvUnset = %v, want AWS_SESSION_TOKEN", plan.EnvUnset)
	}
	if len(plan.Command) != 0 {
		t.Errorf("Command must be filled by caller, got %v", plan.Command)
	}
}

func TestBuildRunPlan_ProxyEnvInjected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	// The fixture declares sni_domains: the plan must carry the full
	// loopback proxy environment plus the whitelist for the host server.
	if got := plan.EnvSet[orchestrator.EnvProxyBridge]; got != proxy.DefaultBridgeAddr {
		t.Errorf("EnvSet[%s] = %q, want %q", orchestrator.EnvProxyBridge, got, proxy.DefaultBridgeAddr)
	}
	url := "http://" + proxy.DefaultBridgeAddr
	if plan.EnvSet["HTTPS_PROXY"] != url {
		t.Errorf("EnvSet[HTTPS_PROXY] = %q, want %q", plan.EnvSet["HTTPS_PROXY"], url)
	}
	if strings.Join(plan.SNIDomains, ",") != "proxy.golang.org" {
		t.Errorf("SNIDomains = %v, want [proxy.golang.org]", plan.SNIDomains)
	}
}

func TestBuildRunPlan_NoSNIDomainsNoProxyEnv(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), "version: \"1\"\n")

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if _, ok := plan.EnvSet[orchestrator.EnvProxyBridge]; ok {
		t.Errorf("proxy marker set without whitelist: %v", plan.EnvSet)
	}
	if len(plan.SNIDomains) != 0 {
		t.Errorf("SNIDomains = %v, want empty", plan.SNIDomains)
	}
}

func TestBuildRunPlan_ExplicitUserConfigMustExist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	if _, err := buildRunPlan(dir, "", missing, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", ""); err == nil {
		t.Error("explicitly requested user config must exist (loud failure beats silent defaults)")
	}
}

func TestBuildRunPlan_ExplicitConfigPathWins(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(t.TempDir(), "other.yaml")
	writeFile(t, custom, "version: \"1\"\n")
	writeFile(t, filepath.Join(dir, ".keg.yaml"), "version: \"1\"\ntemplates: [go]\n")

	plan, err := buildRunPlan(dir, custom, "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.Mounts) != 0 {
		t.Errorf("explicit config path must be used verbatim")
	}
}

func TestBuildRunPlan_OverlayFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayEphemeral, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Overlay.String() != "ephemeral" {
		t.Errorf("overlay = %v, want ephemeral", plan.Overlay)
	}

	diskBase := t.TempDir()
	t.Setenv("KEG_TEST_STORAGE", diskBase)
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, `
paths:
  storage_base: $KEG_TEST_STORAGE/layers
`)
	plan, err = buildRunPlan(dir, "", userCfg, orchestrator.OverlayDisk, "agent-1", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Overlay.String() != "disk" {
		t.Errorf("overlay = %v, want disk", plan.Overlay)
	}
	if plan.DiskLayerRW == "" || plan.DiskLayerWork == "" {
		t.Errorf("disk layer dirs not prepared: rw=%q work=%q", plan.DiskLayerRW, plan.DiskLayerWork)
	}
	if !strings.HasPrefix(plan.DiskLayerRW, diskBase) {
		t.Errorf("layer dir %q must live under storage base %q", plan.DiskLayerRW, diskBase)
	}
}

func TestBuildRunPlan_VarsFromEnvOverride(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"),
		"version: \"1\"\nvars:\n  greeting: repo\n")
	t.Setenv("KEG_VAR_greeting", "environment")

	// The merged var space is not directly observable via Plan yet
	// (templates land in WP-M4); assert no error and document intent.
	if _, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", ""); err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
}

func TestUpstreamProxyFromEnv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no proxy env yields empty", nil, ""},
		{
			name: "https proxy wins over http",
			env:  map[string]string{"HTTP_PROXY": "http://a:1", "HTTPS_PROXY": "http://b:2"},
			want: "b:2",
		},
		{
			name: "lowercase fallback",
			env:  map[string]string{"https_proxy": "http://c:3"},
			want: "c:3",
		},
		{
			name: "scheme is stripped for dialing",
			env:  map[string]string{"HTTPS_PROXY": "http://corp:3128"},
			want: "corp:3128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(k string) string { return tt.env[k] }
			if got := upstreamProxyFromEnv(getenv); got != tt.want {
				t.Fatalf("upstreamProxyFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

const dnsFixtureYAML = `
version: "1"
network:
  sni_domains:
    - proxy.golang.org
  dns:
    upstream: "10.0.0.1:5353"
    hosts:
      db.local.test: "127.0.0.1"
      "*.svc.local.test": "10.0.0.7"
`

func TestBuildRunPlan_DNSEnabledWithEgress(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	// The netns stage serves DNS on loopback :53 inside the sandbox
	// namespace, so the classic resolv.conf works again.
	if plan.ResolvConf == "" {
		t.Fatal("ResolvConf not injected")
	}
	content, rerr := os.ReadFile(plan.ResolvConf) // #nosec G304 -- test-controlled path
	if rerr != nil {
		t.Fatalf("read %s: %v", plan.ResolvConf, rerr)
	}
	if !strings.Contains(string(content), "nameserver 127.0.0.1") {
		t.Errorf("resolv.conf = %q, want loopback nameserver", content)
	}
	// Static mappings are exposed natively via a generated /etc/hosts.
	if plan.HostsFile == "" {
		t.Fatal("HostsFile not injected")
	}
	hcontent, herr := os.ReadFile(plan.HostsFile) // #nosec G304 -- test-controlled path
	if herr != nil {
		t.Fatalf("read %s: %v", plan.HostsFile, herr)
	}
	if !strings.HasPrefix(string(hcontent), "127.0.0.1 localhost\n") {
		t.Errorf("hosts file missing localhost baseline: %q", content)
	}
	if plan.EgressDNS == nil || plan.EgressDNS.Whitelist[0] != "proxy.golang.org" {
		t.Errorf("EgressDNS = %+v", plan.EgressDNS)
	}
}

func TestBuildRunPlan_DNSHostsInEtcHosts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), dnsFixtureYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.HostsFile == "" {
		t.Fatal("HostsFile nil despite dns.hosts")
	}
	content, err := os.ReadFile(plan.HostsFile) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"db.local.test", "*.svc.local.test"} {
		pattern := strings.TrimPrefix(want, "*.")
		if !strings.Contains(string(content), pattern) {
			t.Errorf("hosts file missing entry for %s:\n%s", want, content)
		}
	}
}

func TestBuildRunPlan_DNSHostsAndUpstreamCarried(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), dnsFixtureYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.EgressDNS == nil {
		t.Fatal("EgressDNS nil despite dns config")
	}
	if plan.EgressDNS.Hosts["db.local.test"] != "127.0.0.1" ||
		plan.EgressDNS.Hosts["*.svc.local.test"] != "10.0.0.7" {
		t.Errorf("hosts not carried: %+v", plan.EgressDNS.Hosts)
	}
	if plan.EgressDNS.Upstream != "10.0.0.1:5353" {
		t.Errorf("upstream = %q", plan.EgressDNS.Upstream)
	}
}

func TestBuildRunPlan_DNSDisabledWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), "version: \"1\"\n")

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.HostsFile != "" || plan.EgressDNS != nil || plan.ResolvConf != "" {
		t.Errorf("hosts file/EgressDNS injected without network config: %q %+v",
			plan.HostsFile, plan.EgressDNS)
	}
}

// TestBuildRunPlan_DefaultUpstreamIsHostResolver pins that an egress
// sandbox without explicit dns.upstream forwards to the host's own
// resolver (the kube-dns case: external DNS unreachable, cluster names
// are what matters).
func TestBuildRunPlan_DefaultUpstreamIsHostResolver(t *testing.T) {
	hostNS := firstHostNameserver()
	if hostNS == "" {
		t.Skip("no nameserver in host /etc/resolv.conf")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.EgressDNS == nil || plan.EgressDNS.Upstream != hostNS {
		t.Errorf("EgressDNS.Upstream = %v, want %q", plan.EgressDNS, hostNS)
	}
}

// TestBuildRunPlan_TransparentSkipsProxyVars pins that transparent mode
// leaves the environment untouched (the app may ignore proxies anyway).
func TestBuildRunPlan_TransparentSkipsProxyVars(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
network:
  mode: transparent
  sni_domains:
    - "*.svc.cluster.local"
`)
	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	for k := range plan.EnvSet {
		if strings.Contains(k, "PROXY") {
			t.Errorf("transparent mode injected %s: %v", k, plan.EnvSet)
		}
	}
	if !plan.Transparent {
		t.Error("plan.Transparent not set")
	}
}

func TestBuildRunPlan_TCPEndpointsJoinDNSWhitelist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
network:
  mode: transparent
  tcp_endpoints:
    - host: registry-1.docker.io
      ports: [443]
`)
	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	// Raw-TCP policy correlates resolved IPs back to endpoint names — the
	// names must therefore be resolvable (whitelisted) in channel B.
	if plan.EgressDNS == nil {
		t.Fatal("EgressDNS nil despite tcp_endpoints")
	}
	if !slices.Contains(plan.EgressDNS.Whitelist, "registry-1.docker.io") {
		t.Errorf("Whitelist = %v, want it to contain tcp_endpoints host", plan.EgressDNS.Whitelist)
	}
}

func TestBuildRunPlan_TransparentTCPEndpointsCarried(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
network:
  mode: transparent
  tcp_endpoints:
    - host: registry-1.docker.io
      ports: [443]
`)
	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if !plan.Transparent {
		t.Error("plan.Transparent not set")
	}
	if len(plan.TCPEndpoints) != 1 || plan.TCPEndpoints[0].Host != "registry-1.docker.io" {
		t.Errorf("TCPEndpoints = %+v", plan.TCPEndpoints)
	}
}

func TestBuildRunPlan_PortsBackChannel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
ports:
  - name: dev-server
    port: 8080
    dynamic: true
  - "5432:15432"
`)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}

	if len(plan.Ports) != 2 {
		t.Fatalf("plan.Ports = %d entries, want 2 (%+v)", len(plan.Ports), plan.Ports)
	}
	dyn, stat := plan.Ports[0], plan.Ports[1]

	// Dynamic entry: host port allocated (≠ guest port is NOT required,
	// but it must be a real reservation with a bound listener).
	if dyn.Name != "dev-server" || dyn.Guest != 8080 {
		t.Errorf("dynamic entry = %+v, want dev-server/guest 8080", dyn)
	}
	if dyn.HostPort == 0 {
		t.Error("dynamic entry has no allocated host port")
	}
	if dyn.Listener == nil {
		t.Error("dynamic entry must carry its pre-bound listener (the reservation)")
	}
	if addr := dyn.Listener.Addr().(*net.TCPAddr); addr.Port != dyn.HostPort || !addr.IP.IsLoopback() {
		t.Errorf("dynamic listener = %v, want loopback:%d", addr, dyn.HostPort)
	}

	// Static entry: src:dst mapping without listener.
	if stat.Guest != 5432 || stat.HostPort != 15432 || stat.Listener != nil {
		t.Errorf("static entry = %+v, want 5432->15432 without listener", stat)
	}

	// Env contract: named dynamic port exported for the sandbox, allowlist
	// marker present for the guest forwarder.
	if got := plan.EnvSet["KEG_PORT_DEV_SERVER"]; got != fmt.Sprint(dyn.HostPort) {
		t.Errorf("KEG_PORT_DEV_SERVER = %q, want %q", got, fmt.Sprint(dyn.HostPort))
	}
	if got, want := plan.EnvSet[orchestrator.EnvPortsForward], "8080,5432"; got != want {
		t.Errorf("%s = %q, want %q", orchestrator.EnvPortsForward, got, want)
	}
}

func TestBuildRunPlan_NoPortsNoMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"`)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.Ports) != 0 {
		t.Fatalf("plan.Ports = %v, want none", plan.Ports)
	}
	if _, ok := plan.EnvSet[orchestrator.EnvPortsForward]; ok {
		t.Errorf("%s set without declared ports (deny-by-default violated)", orchestrator.EnvPortsForward)
	}
}

func TestBuildRunPlan_GoTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
env:
  set:
    GOCACHE: /explicit-wins
`)
	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}

	// Template env applied; explicit repo env.set wins over template
	// defaults (additive building block semantics).
	if plan.EnvSet["GOTOOLCHAIN"] != "local" {
		t.Errorf("GOTOOLCHAIN = %q, want local", plan.EnvSet["GOTOOLCHAIN"])
	}
	if got := plan.EnvSet["GOCACHE"]; got != "/explicit-wins" {
		t.Errorf("GOCACHE = %q, want explicit repo value to win", got)
	}
	if plan.EnvSet["GOMODCACHE"] != "/home/sandbox/.cache/go/mod" {
		t.Errorf("GOMODCACHE = %q", plan.EnvSet["GOMODCACHE"])
	}
}

func TestBuildRunPlan_DelegationChannel(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"
delegated_tasks:
  exact:
    - container-build
  raw:
    - cmd: git
      subcommands: [commit]
      forbidden_args_matching: ["https://*"]
`)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.DelegatedTasks.Raw) != 1 || plan.DelegatedTasks.Raw[0].Cmd != "git" {
		t.Errorf("DelegatedTasks not carried into the plan: %+v", plan.DelegatedTasks)
	}
	if plan.EnvSet[orchestrator.EnvDelegation] != "1" {
		t.Errorf("EnvSet[%s] = %q, guest bridge would not start",
			orchestrator.EnvDelegation, plan.EnvSet[orchestrator.EnvDelegation])
	}
	if plan.HooksDir == "" {
		t.Fatal("HooksDir empty — git hook suppression would be disabled")
	}
	info, err := os.Stat(plan.HooksDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("HooksDir %q does not exist as a directory: %v", plan.HooksDir, err)
	}
	entries, err := os.ReadDir(plan.HooksDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("HooksDir must be EMPTY (it suppresses host hooks): entries=%v err=%v", entries, err)
	}
}

func TestBuildRunPlan_NoTasksNoRunnerMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.EnvSet[orchestrator.EnvDelegation] == "1" {
		t.Error("EnvDelegation set without any delegated_tasks")
	}
}

func TestBuildRunPlan_RunnerWhitelistEnvCompat(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)
	t.Setenv("RUNNER_WHITELIST", "container-build, k8s-deploy")

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	found := map[string]bool{}
	for _, name := range plan.DelegatedTasks.Exact {
		found[name] = true
	}
	if !found["k8s-deploy"] {
		t.Errorf("RUNNER_WHITELIST entries not merged into the plan: %v", plan.DelegatedTasks.Exact)
	}
	if found[""] || found[" k8s-deploy"] {
		t.Errorf("whitespace around entries must be trimmed: %v", plan.DelegatedTasks.Exact)
	}
}

func TestBuildRunPlan_RunnerWhitelistAloneEnablesRunner(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)
	t.Setenv("RUNNER_WHITELIST", "deploy")

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if !plan.EnableRunner || plan.EnvSet[orchestrator.EnvDelegation] != "1" {
		t.Error("RUNNER_WHITELIST without repo tasks must still enable delegation")
	}
}

func TestBuildRunPlan_IsolateCaches(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
`)
	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayEphemeral, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.Mounts) == 0 {
		t.Fatal("expected template mounts for go")
	}
	for _, m := range plan.Mounts {
		if m.Mode != config.MountEphemeral {
			t.Errorf("mount %s mode = %v, want ephemeral", m.Dest, m.Mode)
		}
	}
}

func TestBuildRunPlan_IsolatedCacheName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
`)
	diskBase := t.TempDir()
	t.Setenv("KEG_TEST_STORAGE", diskBase)
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, `
paths:
  storage_base: $KEG_TEST_STORAGE/layers
`)
	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayDisk, "test-build", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.Mounts) == 0 {
		t.Fatal("expected template mounts for go")
	}
	for _, m := range plan.Mounts {
		if m.Mode != config.MountDisk {
			t.Errorf("mount %s mode = %v, want disk", m.Dest, m.Mode)
		}
		if m.OverlayRW == "" || m.OverlayWork == "" {
			t.Errorf("mount %s missing overlay paths: rw=%q work=%q", m.Dest, m.OverlayRW, m.OverlayWork)
		}
		if !strings.Contains(m.OverlayRW, "cache-test-build") {
			t.Errorf("mount %s rw path %q must contain cache-test-build", m.Dest, m.OverlayRW)
		}
	}
}

func TestBuildRunPlan_UserConfigCachePathsOverride(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
`)
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, `
paths:
  go_mod_cache: /custom/go/mod
  go_build_cache: /custom/go/build
`)
	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	var modMount, buildMount *config.Mount
	for i := range plan.Mounts {
		if strings.HasSuffix(plan.Mounts[i].Dest, "/mod") {
			modMount = &plan.Mounts[i]
		}
		if strings.HasSuffix(plan.Mounts[i].Dest, "/build") {
			buildMount = &plan.Mounts[i]
		}
	}
	if modMount == nil || modMount.Src != "/custom/go/mod" {
		t.Errorf("mod mount src = %+v, want /custom/go/mod", modMount)
	}
	if buildMount == nil || buildMount.Src != "/custom/go/build" {
		t.Errorf("build mount src = %+v, want /custom/go/build", buildMount)
	}
}

func TestBuildRunPlan_InstanceName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"`)
	tmpBase := t.TempDir()
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, "paths:\n  tmp_base: "+tmpBase+"\n")

	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "worker-1")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	wantDir := filepath.Join(tmpBase, "keg-worker-1")
	if plan.TmpDir != wantDir {
		t.Errorf("TmpDir = %q, want %q", plan.TmpDir, wantDir)
	}
	if info, err := os.Stat(plan.TmpDir); err != nil || !info.IsDir() {
		t.Errorf("instance dir %q not created", plan.TmpDir)
	}
}

func TestBuildRunPlan_InvalidInstanceName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"`)

	for _, invalid := range []string{"worker/1", "../escape", "worker 1", "worker@1"} {
		_, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", invalid)
		if err == nil || !strings.Contains(err.Error(), "invalid instance name") {
			t.Errorf("instance name %q should fail validation, got %v", invalid, err)
		}
	}
}

func TestBuildRunPlan_AuditFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"`)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, "log:\n  audit_file: "+auditPath+"\n")

	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.AuditFile != auditPath {
		t.Errorf("AuditFile = %q, want %q", plan.AuditFile, auditPath)
	}
}

func TestBuildRunPlan_Secrets_InitialFetchAndEnv(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
secrets:
  - name: ai_token
    env: AI_TOKEN_FILE
`)
	script := filepath.Join(t.TempDir(), "get-token")
	writeFile(t, script, "#!/bin/sh\necho -n \"test-ai-token\"")
	_ = os.Chmod(script, 0o750)

	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, `
secret_sources:
  ai_token:
    cmd: ["`+script+`"]
`)

	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	wantSecretDir := filepath.Join(plan.TmpDir, "secrets")
	if plan.SecretDir != wantSecretDir {
		t.Errorf("SecretDir = %q, want %q", plan.SecretDir, wantSecretDir)
	}
	if plan.EnvSet["AI_TOKEN_FILE"] != "/run/secrets/ai_token" {
		t.Errorf("AI_TOKEN_FILE env = %q, want /run/secrets/ai_token", plan.EnvSet["AI_TOKEN_FILE"])
	}
	data, err := os.ReadFile(filepath.Join(wantSecretDir, "ai_token"))
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	if string(data) != "test-ai-token" {
		t.Errorf("secret data = %q, want test-ai-token", string(data))
	}
}

func TestBuildRunPlan_Secrets_MissingSourceFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
secrets:
  - name: missing_sec
`)
	_, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil || !strings.Contains(err.Error(), "missing_sec") {
		t.Fatalf("expected missing secret error, got: %v", err)
	}
}

func TestBuildRunPlan_LandlockConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `version: "1"`)
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, "security:\n  landlock: \"on\"\n")

	plan, err := buildRunPlan(dir, "", userCfg, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if plan.Landlock != "on" {
		t.Errorf("Landlock = %q, want 'on'", plan.Landlock)
	}
	if plan.EnvSet[orchestrator.EnvLandlock] != "on" {
		t.Errorf("EnvSet[%s] = %q, want 'on'", orchestrator.EnvLandlock, plan.EnvSet[orchestrator.EnvLandlock])
	}
}
