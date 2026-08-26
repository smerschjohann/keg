//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSandboxGoTemplateOfflineBuild is the WP-M4 §6.3 DoD test: with the
// builtin `go` template, `go build ./...` works offline inside the sandbox
// from a warm module/build cache mounted read-write from the host — while
// the toolchain itself comes from a GOROOT bound at its host path.
func TestSandboxGoTemplateOfflineBuild(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
`)
	writeFile(t, filepath.Join(dir, "go.mod"), "module hello\n\ngo 1.24\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() { println(\"hello-template\") }\n")

	// Warm caches on the host first: a real host build populates GOCACHE
	// and GOMODCACHE fixtures, proving the sandbox build hits them instead
	// of any network.
	goModCache := t.TempDir()
	goBuildCache := t.TempDir()
	warm := exec.Command("go", "build", "-o", "/dev/null", ".")
	warm.Dir = dir
	warm.Env = append(os.Environ(),
		"GOMODCACHE="+goModCache,
		"GOCACHE="+goBuildCache,
		"GOFLAGS=-mod=mod",
	)
	if out, err := warm.CombinedOutput(); err != nil {
		t.Fatalf("host warm build failed: %v\n%s", err, out)
	}

	script := `cd /repo 2>/dev/null; go version && go build -o hello . && ./hello`
	var out strings.Builder
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.Stdout = &out
	plan.Stderr = &out

	// Template wiring (mirrors buildRunPlan): env defaults plus rw cache
	// mounts; GOROOT outside /usr gets its own ro-bind and PATH entry.
	plan.EnvSet["GOTOOLCHAIN"] = "local"
	plan.EnvSet["GOMODCACHE"] = "/home/sandbox/.cache/go/mod"
	plan.EnvSet["GOCACHE"] = "/home/sandbox/.cache/go/build"
	plan.EnvSet["GOFLAGS"] = "-mod=mod"
	plan.Mounts = append(plan.Mounts,
		config.Mount{Src: goModCache, Dest: plan.EnvSet["GOMODCACHE"], Mode: config.MountRW},
		config.Mount{Src: goBuildCache, Dest: plan.EnvSet["GOCACHE"], Mode: config.MountRW},
	)
	tc := config.DetectToolchainPaths(exec.LookPath, config.HostGoEnv)
	if tc.GoRoot != "" && tc.GoRootNeedsBind() {
		plan.Mounts = append(plan.Mounts,
			config.Mount{Src: tc.GoRoot, Dest: tc.GoRoot, Mode: config.MountRO})
		plan.ExtraPathDirs = []string{tc.GoRoot + "/bin"}
	}

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "go version") {
		t.Errorf("go toolchain not reachable inside sandbox:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "hello-template") {
		t.Errorf("offline build/run failed:\n%s", out.String())
	}
}
