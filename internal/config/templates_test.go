package config

import (
	"strings"
	"testing"
)

func TestExpandTemplates_Go(t *testing.T) {
	t.Parallel()
	mounts, env, err := ExpandTemplates([]string{"go"}, "/home/sandbox", ToolchainPaths{
		GoModCache:   "/host/gomod",
		GoBuildCache: "/host/gobuild",
	})
	if err != nil {
		t.Fatalf("ExpandTemplates: %v", err)
	}
	wantEnv := map[string]string{
		"GOTOOLCHAIN": "local",
		"GOMODCACHE":  "/home/sandbox/.cache/go/mod",
		"GOCACHE":     "/home/sandbox/.cache/go/build",
	}
	for k, want := range wantEnv {
		if env[k] != want {
			t.Errorf("env[%s] = %q, want %q", k, env[k], want)
		}
	}
	if len(env) != len(wantEnv) {
		t.Errorf("unexpected extra env entries: %v", env)
	}
	if len(mounts) != 2 {
		t.Fatalf("mounts = %d, want 2 (%+v)", len(mounts), mounts)
	}
	gotMod := findMount(t, mounts, "/home/sandbox/.cache/go/mod")
	if gotMod.Src != "/host/gomod" || gotMod.Mode != MountRW {
		t.Errorf("mod mount = %+v, want /host/gomod rw", gotMod)
	}
	gotBuild := findMount(t, mounts, "/home/sandbox/.cache/go/build")
	if gotBuild.Src != "/host/gobuild" || gotBuild.Mode != MountRW {
		t.Errorf("build mount = %+v, want /host/gobuild rw", gotBuild)
	}
}

// Without detected caches the go template still pins GOTOOLCHAIN and the
// sandbox cache locations (a cold build then just populates tmpfs/overlay),
// but emits no host mounts.
func TestExpandTemplates_GoWithoutDetection(t *testing.T) {
	t.Parallel()
	mounts, env, err := ExpandTemplates([]string{"go"}, "/home/sandbox", ToolchainPaths{})
	if err != nil {
		t.Fatalf("ExpandTemplates: %v", err)
	}
	if len(mounts) != 0 {
		t.Errorf("no caches detected: mounts = %+v, want none", mounts)
	}
	if env["GOTOOLCHAIN"] != "local" || env["GOMODCACHE"] == "" || env["GOCACHE"] == "" {
		t.Errorf("env incomplete: %v", env)
	}
}

func TestExpandTemplates_FixedPathTemplates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		template   string
		wantEnv    map[string]string
		wantSrc    string // host source of the single cache mount
		wantDest   string
		sandboxSub string // dest is <home>/<sandboxSub>
	}{
		{
			name:       "java maven repository",
			template:   "java",
			wantEnv:    map[string]string{"MAVEN_OPTS": "-Dmaven.repo.local=/home/sandbox/.m2/repository"},
			wantSrc:    "~/.m2",
			wantDest:   ".m2",
			sandboxSub: "",
		},
		{
			name:       "node npm cache",
			template:   "node",
			wantEnv:    map[string]string{"npm_config_cache": "/home/sandbox/.npm"},
			wantSrc:    "~/.npm",
			wantDest:   ".npm",
			sandboxSub: "",
		},
		{
			name:       "python pip cache",
			template:   "python",
			wantEnv:    map[string]string{"PIP_CACHE_DIR": "/home/sandbox/.cache/pip"},
			wantSrc:    "~/.cache/pip",
			wantDest:   ".cache/pip",
			sandboxSub: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mounts, env, err := ExpandTemplates([]string{tt.template}, "/home/sandbox", ToolchainPaths{})
			if err != nil {
				t.Fatalf("ExpandTemplates: %v", err)
			}
			for k, want := range tt.wantEnv {
				if env[k] != want {
					t.Errorf("env[%s] = %q, want %q", k, env[k], want)
				}
			}
			if len(mounts) != 1 {
				t.Fatalf("mounts = %+v, want exactly one", mounts)
			}
			m := mounts[0]
			if m.Src != tt.wantSrc {
				t.Errorf("src = %q, want %q (tilde stays literal; ExpandPath resolves it later)", m.Src, tt.wantSrc)
			}
			if !strings.HasSuffix(m.Dest, tt.wantDest) || !strings.HasPrefix(m.Dest, "/home/sandbox") {
				t.Errorf("dest = %q, want under /home/sandbox/%s", m.Dest, tt.wantDest)
			}
			if m.Mode != MountRW {
				t.Errorf("mode = %q, want rw", m.Mode)
			}
		})
	}
}

func TestExpandTemplates_AdditiveAndUnknownFails(t *testing.T) {
	t.Parallel()
	// Additive: two templates combine their env and mounts.
	mounts, env, err := ExpandTemplates([]string{"go", "node"},
		"/home/sandbox",
		ToolchainPaths{GoModCache: "/h/mod", GoBuildCache: "/h/build"})
	if err != nil {
		t.Fatalf("ExpandTemplates: %v", err)
	}
	if len(mounts) != 3 {
		t.Errorf("combined mounts = %d, want 3", len(mounts))
	}
	if env["GOTOOLCHAIN"] == "" || env["npm_config_cache"] == "" {
		t.Errorf("combined env missing entries: %v", env)
	}

	// Unknown names fail hard (validation normally catches this earlier).
	if _, _, err := ExpandTemplates([]string{"rust"}, "/home/sandbox", ToolchainPaths{}); err == nil {
		t.Error("unknown template must error")
	}
}

func TestDetectToolchainPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		goBin   string
		goEnvFn func(string) (string, error)
		want    ToolchainPaths
	}{
		{
			name:  "go absent yields empty paths",
			goBin: "",
			want:  ToolchainPaths{},
		},
		{
			name:  "go env values are used verbatim",
			goBin: "/usr/local/go/bin/go",
			goEnvFn: func(key string) (string, error) {
				return map[string]string{
					"GOMODCACHE": "/h/mod",
					"GOCACHE":    "/h/cache",
					"GOROOT":     "/usr/local/go",
				}[key], nil
			},
			want: ToolchainPaths{GoModCache: "/h/mod", GoBuildCache: "/h/cache", GoRoot: "/usr/local/go"},
		},
		{
			name:  "failing go env falls back per key",
			goBin: "/usr/bin/go",
			goEnvFn: func(string) (string, error) {
				return "", contextDeadlineExceeded()
			},
			want: ToolchainPaths{}, // no usable fallback without HOME in test; empty is fine-closed
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookPath := func(string) (string, error) {
				if tt.goBin == "" {
					return "", errStub{}
				}
				return tt.goBin, nil
			}
			got := DetectToolchainPaths(lookPath, tt.goEnvFn)
			if got.GoModCache != tt.want.GoModCache || got.GoBuildCache != tt.want.GoBuildCache || got.GoRoot != tt.want.GoRoot {
				t.Errorf("DetectToolchainPaths = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func contextDeadlineExceeded() error { return errStub{} }

type errStub struct{}

func (errStub) Error() string { return "boom" }

func findMount(t *testing.T, mounts []Mount, dest string) Mount {
	t.Helper()
	for _, m := range mounts {
		if m.Dest == dest {
			return m
		}
	}
	t.Fatalf("no mount with dest %q in %+v", dest, mounts)
	return Mount{}
}

func TestCheckCGOToolchain(t *testing.T) {
	t.Parallel()
	lookPathSuccess := func(name string) (string, error) {
		if name == "gcc" {
			return "/usr/bin/gcc", nil
		}
		return "", errStub{}
	}
	if err := CheckCGOToolchain(lookPathSuccess); err != nil {
		t.Errorf("CheckCGOToolchain with gcc: %v", err)
	}

	lookPathFail := func(string) (string, error) {
		return "", errStub{}
	}
	if err := CheckCGOToolchain(lookPathFail); err == nil {
		t.Error("CheckCGOToolchain without compiler should return error")
	}
}
