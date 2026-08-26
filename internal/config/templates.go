package config

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToolchainPaths carries host-side cache/tool locations detected via
// DetectToolchainPaths. Empty fields mean "not detected" — expansions then
// skip the corresponding mounts (fail-closed: nothing is guessed).
type ToolchainPaths struct {
	GoModCache   string
	GoBuildCache string
	GoRoot       string
}

// ExpandTemplates turns builtin language templates (CONCEPT.md §4.6) into
// additional env entries and cache mounts — additive building blocks, so a
// sandbox may combine several. sandboxHome is the in-sandbox HOME; tilde
// sources stay literal here and are resolved by ExpandPath during plan
// building, exactly like user-declared mounts.
//
// Explicit repo env wins over template defaults: the caller applies the
// returned env BEFORE copying repo.Env.Set.
func ExpandTemplates(names []string, sandboxHome string, tc ToolchainPaths) ([]Mount, map[string]string, error) {
	mounts := []Mount{}
	env := map[string]string{}
	for _, name := range names {
		switch name {
		case "go", "golang":
			env["GOTOOLCHAIN"] = "local" // never download toolchains offline
			env["GOMODCACHE"] = sandboxHome + "/.cache/go/mod"
			env["GOCACHE"] = sandboxHome + "/.cache/go/build"
			if tc.GoModCache != "" {
				mounts = append(mounts, Mount{Src: tc.GoModCache, Dest: env["GOMODCACHE"], Mode: MountRW})
			}
			if tc.GoBuildCache != "" {
				mounts = append(mounts, Mount{Src: tc.GoBuildCache, Dest: env["GOCACHE"], Mode: MountRW})
			}
		case "java":
			env["MAVEN_OPTS"] = "-Dmaven.repo.local=" + sandboxHome + "/.m2/repository"
			mounts = append(mounts, Mount{Src: "~/.m2", Dest: sandboxHome + "/.m2", Mode: MountRW})
		case "node":
			env["npm_config_cache"] = sandboxHome + "/.npm"
			mounts = append(mounts, Mount{Src: "~/.npm", Dest: sandboxHome + "/.npm", Mode: MountRW})
		case "python":
			env["PIP_CACHE_DIR"] = sandboxHome + "/.cache/pip"
			mounts = append(mounts, Mount{Src: "~/.cache/pip", Dest: sandboxHome + "/.cache/pip", Mode: MountRW})
		default:
			return nil, nil, fmt.Errorf("unknown template %q (builtin: go, java, node, python)", name)
		}
	}
	return mounts, env, nil
}

// DetectToolchainPaths probes the HOST for language toolchain caches.
// lookPath/goEnv are seams for tests; production passes exec.LookPath and
// a runner around `go env`. Detection is best-effort by design: an absent
// toolchain yields empty fields, never an error — templates still pin the
// sandbox-side locations.
func DetectToolchainPaths(lookPath func(string) (string, error), goEnv func(string) (string, error)) ToolchainPaths {
	var tc ToolchainPaths
	goBin, err := lookPath("go")
	if err != nil || goBin == "" {
		return tc
	}
	tc.GoModCache = probe(goEnv, "GOMODCACHE")
	tc.GoBuildCache = probe(goEnv, "GOCACHE")
	tc.GoRoot = probe(goEnv, "GOROOT")
	return tc
}

func probe(goEnv func(string) (string, error), key string) string {
	v, err := goEnv(key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// HostGoEnv runs `go env <key>` on the host (production seam for
// DetectToolchainPaths).
func HostGoEnv(key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), goEnvTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "env", key).Output() // #nosec G204 -- fixed binary name from PATH, key is a compile-time constant at call sites
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", key, err)
	}
	return string(out), nil
}

const goEnvTimeout = 5 * time.Second

// GoRootNeedsBind reports whether the detected GOROOT lives outside the
// always-bound /usr tree and therefore needs its own ro-bind.
func (t ToolchainPaths) GoRootNeedsBind() bool {
	if t.GoRoot == "" {
		return false
	}
	clean := filepath.Clean(t.GoRoot)
	return clean != "/usr" && !strings.HasPrefix(clean, "/usr/")
}

// CheckCGOToolchain checks whether the host C compiler/linker tools needed for CGO
// (e.g. gcc, clang, or cc) are available on PATH.
func CheckCGOToolchain(lookPath func(string) (string, error)) error {
	for _, cc := range []string{"gcc", "clang", "cc"} {
		if p, err := lookPath(cc); err == nil && p != "" {
			return nil
		}
	}
	return fmt.Errorf("cgo requires a C compiler (gcc, clang, or cc) but none was found on PATH")
}
