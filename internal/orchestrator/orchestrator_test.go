package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
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
// three channel FDs are handed to bwrap via ExtraFiles (fds 3..5 inside
// the sandbox; CONCEPT.md §9).
func TestFDPlan_ExtraFileCount(t *testing.T) {
	if FDPreserved != 3 || FDProxy != 3 || FDDNS != 4 || FDRunner != 5 {
		t.Errorf("FD plan changed unexpectedly: proxy=%d dns=%d runner=%d preserved=%d",
			FDProxy, FDDNS, FDRunner, FDPreserved)
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
