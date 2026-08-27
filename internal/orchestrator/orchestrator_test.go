package orchestrator

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/trust"
)

func basePlan() Plan {
	return Plan{
		RepoRoot:    "/work/repo",
		SandboxHome: "/home/sandbox",
		TmpDir:      "/tmp/keg-i1",
		ResolvConf:  "/tmp/keg-i1/resolv.conf",
		Command:     []string{"/bin/bash"},
	}
}

// TestInvariant_IsolationAlwaysEnforced verifies that the generated argument
// list always carries the hardening flags regardless of configuration
// (THREAT_MODEL.md §8.3: repo config can never weaken isolation silently).
func TestInvariant_IsolationAlwaysEnforced(t *testing.T) {
	args, err := BuildArgs(basePlan())
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"--unshare-all", "--die-with-parent", "--disable-userns"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing isolation flag %q", want)
		}
	}
}

// TestInvariant_WeakBwrapNeedsConsent rejects isolation-weakening bwrap_args
// without security.allow_weak_bwrap; the error must name the exact flag
// (CONCEPT.md §5 validation rules).
func TestInvariant_WeakBwrapNeedsConsent(t *testing.T) {
	tests := []struct {
		name     string
		extra    []string
		wantFlag string
	}{
		{name: "share-net", extra: []string{"--share-net"}, wantFlag: "--share-net"},
		{name: "dev-bind root", extra: []string{"--dev-bind", "/", "/"}, wantFlag: "--dev-bind"},
		{name: "share-net later", extra: []string{"--ro-bind", "/x", "/y", "--share-net"}, wantFlag: "--share-net"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePlan()
			p.BwrapArgs = tt.extra
			p.AllowWeakBwrap = false
			_, err := BuildArgs(p)
			if err == nil {
				t.Fatal("weak bwrap_args must be rejected without consent")
			}
			if !strings.Contains(err.Error(), tt.wantFlag) {
				t.Errorf("error %q must name the offending flag %q", err, tt.wantFlag)
			}

			// With consent the same plan builds fine.
			p.AllowWeakBwrap = true
			if _, err := BuildArgs(p); err != nil {
				t.Errorf("weak bwrap_args with consent must pass: %v", err)
			}
		})
	}
}

// TestInvariant_HostEnvNeverInherited ensures proxy/cloud credentials from
// the host are actively stripped (THREAT_MODEL.md §8.2).
func TestInvariant_HostEnvNeverInherited(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corp-proxy:3128")
	t.Setenv("AWS_SESSION_TOKEN", "leak-me")
	args, err := BuildArgs(basePlan())
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	joined := strings.Join(args, "\x00")
	for _, v := range HostDeniedEnvVars {
		if !strings.Contains(joined, "--unsetenv\x00"+v) && !containsUnsetenvAll(args, v) {
			t.Errorf("host env var %q is not stripped (missing --unsetenv)", v)
		}
	}
}

func containsUnsetenvAll(args []string, name string) bool {
	for i, a := range args {
		if a == "--unsetenv" && i+1 < len(args) && args[i+1] == name {
			return true
		}
	}
	return false
}

func TestBuildArgs_BaseLayout(t *testing.T) {
	args, err := BuildArgs(basePlan())
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	// Expected layout includes env hygiene: every host-denied var must be
	// stripped via --unsetenv before HOME/TMPDIR are set.
	want := make([]string, 0, 36+2*len(HostDeniedEnvVars)+8)
	want = append(want,
		"--unshare-all",
		// The network namespace is provided by the keg netns stage
		// wrapping bwrap (it owns the namespace and serves DNS :53 there),
		// so bwrap retains it instead of creating a fresh one.
		"--share-net",
		"--unshare-user",
		"--die-with-parent",
		"--disable-userns",
		"--proc", "/proc",
		"--dev", "/dev",
		// Fresh tmpfs over host /tmp: workload temp data never leaks.
		"--tmpfs", "/tmp",
		// Base system (proven by run-sandbox.sh): real binds for /bin and
		// /lib (merged-/usr safe), -try for optional locations. /lib64 is
		// required for the dynamic loader. Everything NOT bound here does
		// not exist inside the sandbox (CONCEPT.md visibility model).
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind", "/etc/passwd", "/etc/passwd",
		"--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
		"--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs",
		"--ro-bind-try", "/etc/pki", "/etc/pki",
		"--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--ro-bind-try", "/etc/crypto-policies", "/etc/crypto-policies",
		"--bind", "/work/repo", "/work/repo",
		"--tmpfs", "/home/sandbox",
		"--chdir", "/work/repo",
		"--ro-bind", "/tmp/keg-i1/resolv.conf", "/etc/resolv.conf",
	)
	for _, v := range HostDeniedEnvVars {
		want = append(want, "--unsetenv", v)
	}
	want = append(want,
		"--setenv", "HOME", "/home/sandbox",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "SHELL", "/bin/bash",
		"--setenv", "PATH", "/work/repo/.cache/bin:/home/sandbox/.local/bin:/usr/local/bin:/usr/bin:/bin",
		"--setenv", "KEG_ENV_KEEP", `{"core":["HOME","TMPDIR","SHELL","PATH","CODE_KEG"]}`,
		"--", "/bin/bash",
	)
	got := strings.Join(args, "\n")
	exp := strings.Join(want, "\n")
	if got != exp {
		t.Errorf("arg mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, exp)
	}
}

func TestBuildArgs_CustomMountsSortedByDest(t *testing.T) {
	p := basePlan()
	p.Mounts = []config.Mount{
		{Src: "/zz/data", Dest: "/data/z", Mode: config.MountRO},
		{Src: "/aa/data", Dest: "/data/a", Mode: config.MountRW},
	}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	joined := strings.Join(args, "\n")
	idxA := strings.Index(joined, "--bind\n/aa/data")
	idxZ := strings.Index(joined, "--ro-bind\n/zz/data")
	if idxA < 0 || idxZ < 0 {
		t.Fatalf("custom mounts missing:\n%s", joined)
	}
	if idxA > idxZ {
		t.Errorf("mounts not sorted by dest:\n%s", joined)
	}
}

func TestBuildArgs_MountModes(t *testing.T) {
	tests := []struct {
		name     string
		mode     config.MountMode
		wantFlag string
	}{
		{name: "rw", mode: config.MountRW, wantFlag: "--bind"},
		{name: "ro", mode: config.MountRO, wantFlag: "--ro-bind"},
		{name: "dev", mode: config.MountDev, wantFlag: "--dev-bind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePlan()
			p.Mounts = []config.Mount{{Src: "/src", Dest: "/dest", Mode: tt.mode}}
			args, err := BuildArgs(p)
			if err != nil {
				t.Fatalf("BuildArgs: %v", err)
			}
			joined := strings.Join(args, "\n")
			if !strings.Contains(joined, tt.wantFlag+"\n/src\n/dest") {
				t.Errorf("want %s /src /dest in:\n%s", tt.wantFlag, joined)
			}
		})
	}
}

func TestBuildArgs_TmpfsMountNeedsNoSrc(t *testing.T) {
	p := basePlan()
	p.Mounts = []config.Mount{{Dest: "/scratch", Mode: config.MountTmpfs}}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if !containsPair(args, "--tmpfs", "/scratch") {
		t.Errorf("want --tmpfs /scratch in %v", args)
	}
}

func TestBuildArgs_EnvUnsetBeforeSet(t *testing.T) {
	p := basePlan()
	p.EnvUnset = []string{"AWS_SESSION_TOKEN"}
	p.EnvSet = map[string]string{"LOG_FORMAT": "json"}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	unsetIdx, setIdx := -1, -1
	for i, a := range args {
		switch {
		case a == "--unsetenv" && args[i+1] == "AWS_SESSION_TOKEN":
			unsetIdx = i
		case a == "--setenv" && args[i+1] == "LOG_FORMAT":
			setIdx = i
		}
	}
	if unsetIdx < 0 || setIdx < 0 {
		t.Fatalf("env operations missing: %v", args)
	}
	if unsetIdx > setIdx {
		t.Errorf("--unsetenv must come before --setenv (unset-first semantics)")
	}
}

func TestBuildArgs_OverlayModes(t *testing.T) {
	t.Run("ephemeral uses tmp overlay over repo", func(t *testing.T) {
		p := basePlan()
		p.Overlay = OverlayEphemeral
		args, err := BuildArgs(p)
		if err != nil {
			t.Fatalf("BuildArgs: %v", err)
		}
		if !containsSequence(args, "--overlay-src", "/work/repo", "--tmp-overlay", "/work/repo") {
			t.Errorf("want --overlay-src + --tmp-overlay over repo, got %v", args)
		}
		if containsSequence(args, "--bind", "/work/repo", "/work/repo") {
			t.Errorf("plain rw bind must not coexist with overlay: %v", args)
		}
	})
	t.Run("disk layer persists on host dir", func(t *testing.T) {
		dir := t.TempDir()
		rw := filepath.Join(dir, "rw")
		work := filepath.Join(dir, "work")
		for _, d := range []string{rw, work} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		p := basePlan()
		p.Overlay = OverlayDisk
		p.DiskLayerRW = rw
		p.DiskLayerWork = work
		args, err := BuildArgs(p)
		if err != nil {
			t.Fatalf("BuildArgs: %v", err)
		}
		if !containsSequence(args, "--overlay-src", "/work/repo",
			"--overlay", rw, work, "/work/repo") {
			t.Errorf("want --overlay-src lower + --overlay RWSRC WORKDIR DEST, got %v", args)
		}
	})
	t.Run("mount ephemeral uses tmp overlay over mount source", func(t *testing.T) {
		p := basePlan()
		p.Mounts = []config.Mount{
			{Src: "/home/user/.cache/go/mod", Dest: "/home/sandbox/.cache/go/mod", Mode: config.MountEphemeral},
		}
		args, err := BuildArgs(p)
		if err != nil {
			t.Fatalf("BuildArgs: %v", err)
		}
		if !containsSequence(args, "--overlay-src", "/home/user/.cache/go/mod", "--tmp-overlay", "/home/sandbox/.cache/go/mod") {
			t.Errorf("want --overlay-src + --tmp-overlay over mount src/dest, got %v", args)
		}
		if containsSequence(args, "--bind", "/home/user/.cache/go/mod", "/home/sandbox/.cache/go/mod") {
			t.Errorf("plain bind must not coexist with ephemeral mount: %v", args)
		}
	})
	t.Run("mount disk uses persistent overlay over mount source", func(t *testing.T) {
		p := basePlan()
		p.Mounts = []config.Mount{
			{
				Src:         "/home/user/.cache/go/mod",
				Dest:        "/home/sandbox/.cache/go/mod",
				Mode:        config.MountDisk,
				OverlayRW:   "/var/lib/containers/storage/sandbox/cache-test/mod-rw",
				OverlayWork: "/var/lib/containers/storage/sandbox/cache-test/mod-work",
			},
		}
		args, err := BuildArgs(p)
		if err != nil {
			t.Fatalf("BuildArgs: %v", err)
		}
		if !containsSequence(args, "--overlay-src", "/home/user/.cache/go/mod",
			"--overlay", "/var/lib/containers/storage/sandbox/cache-test/mod-rw",
			"/var/lib/containers/storage/sandbox/cache-test/mod-work",
			"/home/sandbox/.cache/go/mod") {
			t.Errorf("want --overlay-src + --overlay RW WORK DEST, got %v", args)
		}
	})
	t.Run("has overlay detection", func(t *testing.T) {
		p := basePlan()
		if p.HasOverlay() {
			t.Errorf("basePlan should not have overlay")
		}
		p.Overlay = OverlayEphemeral
		if !p.HasOverlay() {
			t.Errorf("OverlayEphemeral should have overlay")
		}
		p.Overlay = OverlayPlain
		p.Mounts = []config.Mount{
			{Src: "/a", Dest: "/b", Mode: config.MountEphemeral},
		}
		if !p.HasOverlay() {
			t.Errorf("MountEphemeral should have overlay")
		}
		p.Mounts = []config.Mount{
			{Src: "/a", Dest: "/b", Mode: config.MountDisk},
		}
		if !p.HasOverlay() {
			t.Errorf("MountDisk should have overlay")
		}
	})
}

func TestBuildArgs_SecretsDirReadOnly(t *testing.T) {
	p := basePlan()
	p.SecretDir = "/tmp/keg-i1/secrets"
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if !containsSequence(args, "--ro-bind", "/tmp/keg-i1/secrets", "/run/secrets") {
		t.Errorf("secret dir must be ro-bound to /run/secrets: %v", args)
	}
}

func TestBuildArgs_ExtraArgsAppendedLast(t *testing.T) {
	p := basePlan()
	p.AllowWeakBwrap = true
	p.BwrapArgs = []string{"--setenv", "BASH_ENV", "/etc/keg/bash-env"}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	lastExtra := -1
	for i, a := range args[:sep] {
		if a == "/etc/keg/bash-env" {
			lastExtra = i
		}
	}
	if lastExtra != sep-1 {
		t.Errorf("extra bwrap_args must be the last args before --, got %v", args)
	}
}

func TestBuildArgs_DeterministicAcrossRuns(t *testing.T) {
	p := basePlan()
	p.Mounts = []config.Mount{
		{Src: "/b", Dest: "/d2", Mode: config.MountRO},
		{Src: "/a", Dest: "/d1", Mode: config.MountRO},
	}
	a1, err := BuildArgs(p)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := BuildArgs(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a1, "\x00") != strings.Join(a2, "\x00") {
		t.Error("BuildArgs must be deterministic")
	}
}

// TestFDPlan_ExtraFileCount pins the FD inheritance contract: exactly the
// four channel FDs are handed to bwrap via ExtraFiles (fds 3..6 inside the
// sandbox; CONCEPT.md §9 — proxy, DNS, runner, port back-channel).
func TestFDPlan_ExtraFileCount(t *testing.T) {
	if FDPreserved != 4 || FDProxy != 3 || FDDNS != 4 || FDRunner != 5 || FDPorts != 6 {
		t.Errorf("FD plan changed unexpectedly: proxy=%d dns=%d runner=%d ports=%d preserved=%d",
			FDProxy, FDDNS, FDRunner, FDPorts, FDPreserved)
	}
}

func containsPair(args []string, key, val string) bool {
	for i, a := range args {
		if a == key && i+1 < len(args) && args[i+1] == val {
			return true
		}
	}
	return false
}

func containsSequence(args []string, seq ...string) bool {
	if len(seq) == 0 {
		return false
	}
outer:
	for i := 0; i+len(seq) <= len(args); i++ {
		for j := range seq {
			if args[i+j] != seq[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func TestIsOverlayBusy(t *testing.T) {
	tests := []struct {
		name string
		res  waitResult
		want bool
	}{
		{
			name: "overlay mount busy",
			res: waitResult{code: 1, stderr: "bwrap: Can't make overlay mount on /newroot/x with options " +
				"upperdir=...,workdir=...,lowerdir=...,userxattr: Device or resource busy"},
			want: true,
		},
		{
			name: "setup failure without busy (e.g. missing bind source)",
			res:  waitResult{code: 1, stderr: "bwrap: Can't find source path /does/not/exist"},
			want: false,
		},
		{
			name: "busy but different cause",
			res:  waitResult{code: 1, stderr: "bwrap: something else: Device or resource busy"},
			want: false,
		},
		{
			name: "successful run",
			res:  waitResult{code: 0},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOverlayBusy(tt.res); got != tt.want {
				t.Errorf("isOverlayBusy(%+v) = %v, want %v", tt.res, got, tt.want)
			}
		})
	}
}

// TestBuildArgs_GuestEntrypointRouting pins the M2 wiring: when the plan
// carries the keg binary path, the sandbox command routes through the
// reexec'd guest (bound read-only into the sandbox), so bridges, env
// hygiene and exit-code mapping apply to every workload.
func TestBuildArgs_GuestEntrypointRouting(t *testing.T) {
	p := basePlan()
	p.SelfExe = "/opt/keg/keg"
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--tmpfs\x00/.keg") {
		t.Errorf("guest staging dir missing:\n%s", joined)
	}
	if !strings.Contains(joined, "--ro-bind\x00/opt/keg/keg\x00/.keg/keg") {
		t.Errorf("self bind missing:\n%s", joined)
	}
	tail := args[len(args)-3:]
	wantTail := []string{"/.keg/keg", GuestCommandName, "/bin/bash"}
	for i, w := range wantTail {
		if tail[i] != w {
			t.Fatalf("command tail = %v, want %v", tail, wantTail)
		}
	}
}

// Without SelfExe the command stays verbatim (used by focused tests).
func TestBuildArgs_NoSelfExeKeepsCommandVerbatim(t *testing.T) {
	args, err := BuildArgs(basePlan())
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if tail := args[len(args)-1:]; tail[0] != "/bin/bash" {
		t.Fatalf("last arg = %q, want plain /bin/bash", tail[0])
	}
}

// TestBuildArgs_ExtraPathDirs puts toolchain binaries (e.g. GOROOT/bin)
// ahead of the default PATH when a template binds a toolchain outside the
// always-bound /usr tree.
func TestBuildArgs_ExtraPathDirs(t *testing.T) {
	var p Plan
	p.RepoRoot = "/repo"
	p.SandboxHome = "/home/sandbox"
	p.ExtraPathDirs = []string{"/usr/local/go/bin"}

	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	want := "/usr/local/go/bin:/repo/.cache/bin:/home/sandbox/.local/bin:/usr/local/bin:/usr/bin:/bin"
	if !containsPair(args, "--setenv", "PATH") || !slices.Contains(args, want) {
		t.Errorf("PATH not extended correctly:\n%s", strings.Join(args, "\n"))
	}
}

func TestBuildArgs_DelegationChannel(t *testing.T) {
	plan := Plan{
		RepoRoot:     "/repo",
		SandboxHome:  "/home/sb",
		SelfExe:      "/host/bin/keg",
		EnableRunner: true,
		EnvSet:       map[string]string{EnvDelegation: "1"},
	}
	args, err := BuildArgs(plan)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	argStr := strings.Join(args, "\x00")
	if !strings.Contains(argStr, "--tmpfs\x00/run") {
		t.Errorf("--tmpfs /run missing from args:\n%v", args)
	}
	if !strings.Contains(argStr, "--setenv\x00"+EnvDelegation+"\x001") {
		t.Errorf("%s marker not exported to the sandbox:\n%v", EnvDelegation, args)
	}

	// The delegate client must be reachable via PATH once the guest binary
	// is bound into the sandbox.
	var path string
	for i, a := range args {
		if a == "PATH" && i+1 < len(args) {
			path = args[i+1]
		}
	}
	if !strings.Contains(path, "/.keg") {
		t.Errorf("PATH = %q, want /.keg entry so `keg delegate` resolves", path)
	}
}

func approveRepo(t *testing.T, repoDir string, content []byte) {
	t.Helper()
	storePath := trust.DefaultTrustPath()
	store, _ := trust.LoadFile(storePath)
	_, _ = trust.Approve(store, repoDir, content, nil)
	_ = trust.SaveFile(storePath, store)
}

func TestBuildPlan_UserConfigAdditiveMountsAndNetwork(t *testing.T) {
	repoDir := t.TempDir()
	repoYAML := "version: \"1\"\n"
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte(repoYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte(repoYAML))

	userYAML := `
mounts:
  - src: ~/.gemini
    dest: /home/sandbox/.gemini
    mode: rw
network:
  mode: transparent
  dns:
    enabled: true
    hosts:
      custom.local: 10.0.0.99
  sni_domains:
    - daily-cloudcode-pa.googleapis.com
  tcp_endpoints:
    - host: daily-cloudcode-pa.googleapis.com
      ports: [443]
env:
  set:
    CUSTOM_USER_ENV: "enabled"
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, _, err := BuildPlan(repoDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "test-user-plan")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if !plan.Transparent {
		t.Errorf("plan.Transparent = false, want true from user config")
	}
	if len(plan.Mounts) != 1 || plan.Mounts[0].Dest != "/home/sandbox/.gemini" {
		t.Errorf("plan.Mounts = %v, want additive ~/.gemini mount", plan.Mounts)
	}
	if len(plan.SNIDomains) != 1 || plan.SNIDomains[0] != "daily-cloudcode-pa.googleapis.com" {
		t.Errorf("plan.SNIDomains = %v, want daily-cloudcode-pa.googleapis.com", plan.SNIDomains)
	}
	if len(plan.TCPEndpoints) != 1 || plan.TCPEndpoints[0].Host != "daily-cloudcode-pa.googleapis.com" {
		t.Errorf("plan.TCPEndpoints = %v, want daily-cloudcode-pa endpoint", plan.TCPEndpoints)
	}
	if plan.EgressDNS == nil || plan.EgressDNS.Hosts["custom.local"] != "10.0.0.99" {
		t.Errorf("plan.EgressDNS hosts = %v, want custom.local", plan.EgressDNS)
	}
	if plan.EnvSet["CUSTOM_USER_ENV"] != "enabled" {
		t.Errorf("plan.EnvSet[CUSTOM_USER_ENV] = %q, want enabled", plan.EnvSet["CUSTOM_USER_ENV"])
	}
}

func TestBuildPlan_WithoutRepoLocalFile(t *testing.T) {
	emptyDir := t.TempDir() // has NO .keg.yaml

	userYAML := `
vars:
  global_flag: "active"
env:
  set:
    TEST_VAR: "fallback"
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, _, err := BuildPlan(emptyDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "test-empty-repo")
	if err != nil {
		t.Fatalf("BuildPlan without .keg.yaml must succeed, got err: %v", err)
	}

	if plan.RepoRoot != emptyDir {
		t.Errorf("plan.RepoRoot = %q, want %q", plan.RepoRoot, emptyDir)
	}
	if plan.EnvSet["TEST_VAR"] != "fallback" {
		t.Errorf("plan.EnvSet[TEST_VAR] = %q, want fallback", plan.EnvSet["TEST_VAR"])
	}
}

// TestBuildArgs_SecretPathBindsMountedOverSecretDir pins the mount order:
// single-file secret binds must come AFTER the directory bind so they win.
func TestBuildArgs_SecretPathBindsMountedOverSecretDir(t *testing.T) {
	p := basePlan()
	p.SecretDir = "/tmp/keg-i1/secrets"
	p.SecretPathBinds = []SecretBind{{
		HostPath:  "/host/keys/api-key",
		GuestPath: "/run/secrets/api_key",
	}}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	dirIdx := slices.Index(args, "/run/secrets") // first hit = "--dir" value of dir bind
	if dirIdx < 0 || args[dirIdx-1] != "--dir" {
		t.Fatalf("expected --dir /run/secrets for the directory bind, got %v", args)
	}
	fileIdx := slices.Index(args, "/host/keys/api-key")
	if fileIdx < 0 {
		t.Fatalf("secret file not bound at all: %v", args)
	}
	if fileIdx < dirIdx+2 { // must follow the whole-directory ro-bind pair
		t.Fatalf("file bind must come after directory bind: %v", args)
	}
}

// TestBuildArgs_SecretPathBindsWithoutFetchedDir pins that path-mounted
// secrets create /run/secrets themselves when nothing was fetched.
func TestBuildArgs_SecretPathBindsWithoutFetchedDir(t *testing.T) {
	p := basePlan()
	p.SecretPathBinds = []SecretBind{{
		HostPath:  "/host/keys/api-key",
		GuestPath: "/run/secrets/api_key",
	}}
	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	for _, want := range []string{"--dir", "/run/secrets", "--ro-bind", "/host/keys/api-key", "/run/secrets/api_key"} {
		if !slices.Contains(args, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
}

// TestBuildPlan_AlwaysSecretInjectedWithoutRepoNeed pins that a secret
// source flagged with `always: true` is injected into every sandbox, even
// when no .keg.yaml declares the need.
func TestBuildPlan_AlwaysSecretInjectedWithoutRepoNeed(t *testing.T) {
	repoDir := t.TempDir()
	// Repo declares NO secrets at all.
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte("version: \"1\"\n"))
	script := filepath.Join(t.TempDir(), "genkey")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho -n always-token\n"), 0o750); err != nil {
		t.Fatal(err)
	}

	userYAML := `
secret_sources:
  ai_secret_key:
    cmd: ["` + script + `"]
    always: true
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, _, err := BuildPlan(repoDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "test-always-secret")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.SecretDir == "" {
		t.Fatalf("plan.SecretDir is empty: always source must be mounted for every repo")
	}
	if len(plan.Secrets) != 1 || plan.Secrets[0].Name != "ai_secret_key" {
		t.Errorf("plan.Secrets = %+v, want [ai_secret_key]", plan.Secrets)
	}
}

// TestBuildPlan_RepoOverrideSecretNeed pins that a `secrets:` need list in
// the matched repos[] override of the user config adds secrets to the plan,
// with the env mapping applied.
func TestBuildPlan_RepoOverrideSecretNeed(t *testing.T) {
	repoDir := t.TempDir()
	// Repo .keg.yaml declares nothing; the need comes from the user
	// config's repos[] override matching this path.
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte("version: \"1\"\n"))
	script := filepath.Join(t.TempDir(), "gen-db")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho -n db-pass\n"), 0o750); err != nil {
		t.Fatal(err)
	}

	userYAML := `
secret_sources:
  db_password:
    cmd: ["` + script + `"]
repos:
  "` + repoDir + `":
    secrets:
      - name: db_password
        env: DB_PASSWORD_FILE
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, _, err := BuildPlan(repoDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "test-repo-override-secret")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Secrets) != 1 || plan.Secrets[0].Name != "db_password" {
		t.Errorf("plan.Secrets = %+v, want [db_password]", plan.Secrets)
	}
	if plan.EnvSet["DB_PASSWORD_FILE"] != "/run/secrets/db_password" {
		t.Errorf("plan.EnvSet[DB_PASSWORD_FILE] = %q, want /run/secrets/db_password", plan.EnvSet["DB_PASSWORD_FILE"])
	}
}

func TestBuildPlan_SecretSourcesTemplateExpansion(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte("version: \"1\"\n"))

	script := filepath.Join(t.TempDir(), "gen-token")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho -n \"$1 $2 $3\"\n"), 0o750); err != nil {
		t.Fatal(err)
	}

	userYAML := `
vars:
  token_ttl: "1500"
secret_sources:
  ai_secret_key:
    cmd: ["` + script + `", "{{ .Vars.instance }}", "{{ .Vars.token_ttl }}", "{{ .Vars.secret_name }}"]
    always: true
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cliVars := map[string]string{"token_ttl": "2400"}
	plan, _, err := BuildPlan(repoDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "my-sandbox-inst", cliVars)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	secretPath := filepath.Join(plan.SecretDir, "ai_secret_key")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	want := "my-sandbox-inst 2400 ai_secret_key"
	if string(data) != want {
		t.Errorf("secret content = %q, want %q", string(data), want)
	}
	if plan.SecretTemplateCtx.Vars["instance"] != "my-sandbox-inst" {
		t.Errorf("SecretTemplateCtx instance = %q, want my-sandbox-inst", plan.SecretTemplateCtx.Vars["instance"])
	}
}

func TestBuildPlan_TrustGate(t *testing.T) {
	repoDir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", trustDir)

	cfgContent := []byte("version: \"1\"\nenv:\n  set:\n    TEST_KEY: \"val\"\n")
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), cfgContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Untrusted repo config in non-TTY -> BuildPlan fails with trust error
	_, _, err := BuildPlan(repoDir, "", "", OverlayPlain, "", OverlayPlain, "", "test-trust-untrusted")
	if err == nil {
		t.Fatal("BuildPlan with untrusted repo config should fail, got nil error")
	}
	if !strings.Contains(err.Error(), "keg trust") {
		t.Errorf("expected error to mention 'keg trust', got: %v", err)
	}

	// 2. Trust the repo config
	trustStorePath := filepath.Join(trustDir, "keg", "trust.yaml")
	store, _ := trust.LoadFile(trustStorePath)
	_, err = trust.Approve(store, repoDir, cfgContent, nil)
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if err := trust.SaveFile(trustStorePath, store); err != nil {
		t.Fatalf("SaveFile failed: %v", err)
	}

	// 3. Now BuildPlan succeeds
	plan, _, err := BuildPlan(repoDir, "", "", OverlayPlain, "", OverlayPlain, "", "test-trust-trusted")
	if err != nil {
		t.Fatalf("BuildPlan after trust approval failed: %v", err)
	}
	if plan.EnvSet["TEST_KEY"] != "val" {
		t.Errorf("plan.EnvSet[TEST_KEY] = %q, want val", plan.EnvSet["TEST_KEY"])
	}
}

func TestBuildArgs_EnvKeepMarker_ListMode(t *testing.T) {
	p := basePlan()
	p.EnvInherit = []string{"LANG", "TERM"}
	p.EnvSet = map[string]string{"CUSTOM": "1"}

	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}

	// Verify KEG_ENV_KEEP is set in bwrap args
	var markerVal string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--setenv" && args[i+1] == EnvKeepMarkerName {
			markerVal = args[i+2]
			break
		}
	}
	if markerVal == "" {
		t.Fatalf("missing %s marker in args: %v", EnvKeepMarkerName, args)
	}
	if !strings.Contains(markerVal, `"inherit":["LANG","TERM"]`) {
		t.Errorf("markerVal missing inherit vars: %s", markerVal)
	}
	if !strings.Contains(markerVal, `"CUSTOM":"1"`) {
		t.Errorf("markerVal missing custom set var: %s", markerVal)
	}
}

func TestBuildArgs_EnvKeepMarker_AllMode(t *testing.T) {
	p := basePlan()
	p.EnvInheritAll = true

	args, err := BuildArgs(p)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}

	var markerVal string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--setenv" && args[i+1] == EnvKeepMarkerName {
			markerVal = args[i+2]
			break
		}
	}
	if markerVal == "" {
		t.Fatalf("missing %s marker in args: %v", EnvKeepMarkerName, args)
	}
	if !strings.Contains(markerVal, `"all":true`) {
		t.Errorf("markerVal expected all:true, got: %s", markerVal)
	}
}

func TestInvariant_EnvPassthroughDeniedNameRejected(t *testing.T) {
	tests := []struct {
		name       string
		deniedName string
	}{
		{"HTTP_PROXY", "HTTP_PROXY"},
		{"AWS_SESSION_TOKEN", "AWS_SESSION_TOKEN"},
		{"OPENAI_API_KEY", "OPENAI_API_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir := t.TempDir()
			cfgYAML := `
version: "1"
env:
  inherit:
    - ` + tt.deniedName + `
`
			if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte(cfgYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			approveRepo(t, repoDir, []byte(cfgYAML))

			_, _, err := BuildPlan(repoDir, "", "", OverlayPlain, "", OverlayPlain, "", "test-denied-passthrough")
			if err == nil {
				t.Fatalf("expected BuildPlan to reject passthrough of %s, got nil error", tt.deniedName)
			}
			if !strings.Contains(err.Error(), tt.deniedName) {
				t.Errorf("error %q should mention denied name %s", err.Error(), tt.deniedName)
			}
			if !strings.Contains(err.Error(), "-e") && !strings.Contains(err.Error(), "env.set") {
				t.Errorf("error %q should mention explicit setting (-e or env.set)", err.Error())
			}
		})
	}
}

func TestBuildPlan_EnvMergeOrder(t *testing.T) {
	repoDir := t.TempDir()
	cfgYAML := `
version: "1"
env:
  set:
    VAR_CONFLICT: "repo"
    REPO_ONLY: "repo"
  inherit:
    - REPO_INHERIT
`
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte(cfgYAML))

	userYAML := `
env:
  set:
    VAR_CONFLICT: "global"
    GLOBAL_ONLY: "global"
  inherit:
    - GLOBAL_INHERIT
repos:
  "` + repoDir + `":
    env:
      set:
        VAR_CONFLICT: "override"
      inherit:
        - OVERRIDE_INHERIT
`
	userFile := filepath.Join(t.TempDir(), "user-config.yaml")
	if err := os.WriteFile(userFile, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, _, err := BuildPlan(repoDir, "", userFile, OverlayPlain, "", OverlayPlain, "", "test-merge-order")
	if err != nil {
		t.Fatalf("BuildPlan failed: %v", err)
	}

	// Order: User-global < Repo < repos[] override
	// VAR_CONFLICT: global -> repo -> override => "override"
	if plan.EnvSet["VAR_CONFLICT"] != "override" {
		t.Errorf("plan.EnvSet[VAR_CONFLICT] = %q, want override", plan.EnvSet["VAR_CONFLICT"])
	}
	if plan.EnvSet["GLOBAL_ONLY"] != "global" {
		t.Errorf("plan.EnvSet[GLOBAL_ONLY] = %q, want global", plan.EnvSet["GLOBAL_ONLY"])
	}
	if plan.EnvSet["REPO_ONLY"] != "repo" {
		t.Errorf("plan.EnvSet[REPO_ONLY] = %q, want repo", plan.EnvSet["REPO_ONLY"])
	}

	// Inherit should contain union of all three
	wantInherit := []string{"GLOBAL_INHERIT", "REPO_INHERIT", "OVERRIDE_INHERIT"}
	for _, w := range wantInherit {
		if !slices.Contains(plan.EnvInherit, w) {
			t.Errorf("plan.EnvInherit = %v, missing %s", plan.EnvInherit, w)
		}
	}
}

func TestInvariant_EnvUnsetBeatsInherit(t *testing.T) {
	repoDir := t.TempDir()
	cfgYAML := `
version: "1"
env:
  inherit:
    - CONFLICT_VAR
    - KEEP_VAR
  unset:
    - CONFLICT_VAR
`
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte(cfgYAML))

	plan, _, err := BuildPlan(repoDir, "", "", OverlayPlain, "", OverlayPlain, "", "test-unset-beats-inherit")
	if err != nil {
		t.Fatalf("BuildPlan failed: %v", err)
	}

	if slices.Contains(plan.EnvInherit, "CONFLICT_VAR") {
		t.Errorf("plan.EnvInherit should NOT contain CONFLICT_VAR because it is unset: %v", plan.EnvInherit)
	}
	if !slices.Contains(plan.EnvInherit, "KEEP_VAR") {
		t.Errorf("plan.EnvInherit should contain KEEP_VAR: %v", plan.EnvInherit)
	}

	// Test in guest execution
	env := BuildKeepEnv([]byte(`{
		"inherit": ["CONFLICT_VAR", "KEEP_VAR"],
		"unset": ["CONFLICT_VAR"]
	}`), []string{"CONFLICT_VAR=leak", "KEEP_VAR=ok"})

	envMap := make(map[string]string)
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	if _, ok := envMap["CONFLICT_VAR"]; ok {
		t.Errorf("CONFLICT_VAR should be unset in workload environment, got %q", envMap["CONFLICT_VAR"])
	}
	if envMap["KEEP_VAR"] != "ok" {
		t.Errorf("KEEP_VAR = %q, want 'ok'", envMap["KEEP_VAR"])
	}
}

func TestInvariant_SetBeatsInheritedValue(t *testing.T) {
	env := BuildKeepEnv([]byte(`{
		"inherit": ["MY_VAR"],
		"set": {"MY_VAR": "explicit_value"}
	}`), []string{"MY_VAR=host_value"})

	envMap := make(map[string]string)
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	if envMap["MY_VAR"] != "explicit_value" {
		t.Errorf("MY_VAR = %q, want 'explicit_value' (set beats inherit)", envMap["MY_VAR"])
	}
}

func TestAddPortsToPlan(t *testing.T) {
	plan := Plan{
		EnvSet: make(map[string]string),
	}

	specs := []config.PortSpec{
		{Name: "web", Guest: 8080, Dynamic: true},
		{Guest: 3000, Host: 3000},
	}

	if err := AddPortsToPlan(&plan, specs); err != nil {
		t.Fatalf("AddPortsToPlan: %v", err)
	}

	if len(plan.Ports) != 2 {
		t.Fatalf("plan.Ports has %d entries, want 2", len(plan.Ports))
	}

	dyn := plan.Ports[0]
	if dyn.Name != "web" || dyn.Guest != 8080 || dyn.HostPort == 0 || dyn.Listener == nil {
		t.Errorf("dynamic entry = %+v, want valid listener and host port", dyn)
	}
	defer func() {
		if dyn.Listener != nil {
			_ = dyn.Listener.Close()
		}
	}()

	stat := plan.Ports[1]
	if stat.Guest != 3000 || stat.HostPort != 3000 {
		t.Errorf("static entry = %+v, want 3000->3000", stat)
	}

	if got := plan.EnvSet["KEG_PORT_WEB"]; got != fmt.Sprint(dyn.HostPort) {
		t.Errorf("KEG_PORT_WEB = %q, want %d", got, dyn.HostPort)
	}
	if got, want := plan.EnvSet[EnvPortsForward], "8080,3000"; got != want {
		t.Errorf("%s = %q, want %q", EnvPortsForward, got, want)
	}
}

func TestInvariant_PortPublishBindsOnlyLoopback(t *testing.T) {
	// 1. Rejects non-loopback IP and 0.0.0.0
	for _, invalidIP := range []string{"192.168.1.1:8080:80", "0.0.0.0:8080:80", "[::]:8080:80"} {
		_, err := config.ParsePublishFlag(invalidIP)
		if err == nil || !strings.Contains(err.Error(), "only binds on loopback") {
			t.Fatalf("IP %q must be rejected, got: %v", invalidIP, err)
		}
	}

	// 2. Dynamic port listener created by AddPortsToPlan binds only on loopback
	plan := Plan{}
	spec, err := config.ParsePublishFlag(":8080")
	if err != nil {
		t.Fatalf("ParsePublishFlag: %v", err)
	}
	if err := AddPortsToPlan(&plan, []config.PortSpec{spec}); err != nil {
		t.Fatalf("AddPortsToPlan: %v", err)
	}
	if len(plan.Ports) != 1 {
		t.Fatalf("plan.Ports = %d, want 1", len(plan.Ports))
	}
	p := plan.Ports[0]
	if p.Listener == nil {
		t.Fatal("dynamic port missing listener")
	}
	defer func() { _ = p.Listener.Close() }()
	addr, ok := p.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr is %T, want *net.TCPAddr", p.Listener.Addr())
	}
	if !addr.IP.IsLoopback() {
		t.Errorf("listener IP is %v, want loopback", addr.IP)
	}
}

func TestBuildPlan_LandlockWritableMounts(t *testing.T) {
	repoDir := t.TempDir()
	repoYAML := `version: "1"
mounts:
  - src: /tmp/custom-rw
    dest: /var/cache/myapp
    mode: rw
  - src: /tmp/custom-ro
    dest: /opt/readonly
    mode: ro
  - src: /tmp/custom-eph
    dest: /data/ephemeral
    mode: ephemeral
`
	if err := os.WriteFile(filepath.Join(repoDir, ".keg.yaml"), []byte(repoYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	approveRepo(t, repoDir, []byte(repoYAML))

	plan, _, err := BuildPlan(repoDir, "", "", OverlayPlain, "", OverlayPlain, "", "test-landlock-mounts")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	writableEnv := plan.EnvSet[EnvLandlockWritable]
	if writableEnv == "" {
		t.Fatalf("plan.EnvSet[%s] is empty, expected writable mount destinations", EnvLandlockWritable)
	}
	parts := strings.Split(writableEnv, ",")
	if !slices.Contains(parts, "/var/cache/myapp") {
		t.Errorf("expected /var/cache/myapp in %s, got: %v", EnvLandlockWritable, parts)
	}
	if !slices.Contains(parts, "/data/ephemeral") {
		t.Errorf("expected /data/ephemeral in %s, got: %v", EnvLandlockWritable, parts)
	}
	if slices.Contains(parts, "/opt/readonly") {
		t.Errorf("read-only mount /opt/readonly should NOT be in %s, got: %v", EnvLandlockWritable, parts)
	}
}

func TestUnshareStageArgv(t *testing.T) {
	cfg := &stageConfig{
		BwrapPath: "/usr/bin/bwrap",
		Args:      []string{"--ro-bind", "/", "/"},
	}
	argv, envJSON, err := unshareStageArgv("/usr/bin/unshare", "/usr/bin/keg", cfg)
	if err != nil {
		t.Fatalf("unshareStageArgv: %v", err)
	}
	if envJSON == "" {
		t.Fatal("expected non-empty envJSON")
	}
	wantFlags := []string{
		"-U",
		fmt.Sprintf("--map-users=%d:%d:1", os.Getuid(), os.Getuid()),
		fmt.Sprintf("--map-groups=%d:%d:1", os.Getgid(), os.Getgid()),
		"-n",
		"-m",
		"-p",
		"--fork",
		"--keep-caps",
	}
	for _, flag := range wantFlags {
		if !slices.Contains(argv, flag) {
			t.Errorf("argv %v missing expected flag %q", argv, flag)
		}
	}
	if argv[len(argv)-1] != NetnsStageCommandName {
		t.Errorf("argv last element = %q, want %q", argv[len(argv)-1], NetnsStageCommandName)
	}
}
