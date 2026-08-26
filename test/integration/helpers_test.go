//go:build integration

// Package integration verifies real bubblewrap sandbox behavior (WP-M1
// DoD). Tests skip visibly with the reason when bwrap is absent — never
// silently (AGENTS.md §1).
package integration

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

const repoConfig = `
version: "1"
env:
  set:
    SANDBOX_MARKER: inside
`

func findBwrap(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skipf("bubblewrap not installed, skipping integration test: %v", err)
	}
}

// runInSandbox launches a sandbox rooted at dir running /bin/sh -c script
// and returns captured output plus exit code.
func runInSandbox(t *testing.T, dir string, overlay orchestrator.Overlay, script string) (string, int) {
	t.Helper()
	return runInSandboxWithConfig(t, dir, repoConfig, overlay, script, nil, nil)
}

// runInSandboxWithConfig launches with a custom repo config; hooks mirror
// the production wiring points: prepare mutates the Plan before launch
// (env injection like buildRunPlan), postLaunch serves channels afterwards.
func runInSandboxWithConfig(
	t *testing.T,
	dir, cfgContent string,
	overlay orchestrator.Overlay,
	script string,
	prepare func(plan *orchestrator.Plan),
	postLaunch func(sb *orchestrator.Sandbox),
) (string, int) {
	t.Helper()
	findBwrap(t)
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()

	var out bytes.Buffer
	plan, err := planFor(dir, tmpDir, overlay, []string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	plan.Stdout = &out
	plan.Stderr = &out
	if prepare != nil {
		prepare(&plan)
	}

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	if postLaunch != nil {
		postLaunch(sb)
	}
	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	return out.String(), code
}

func planFor(repoRoot, tmpDir string, overlay orchestrator.Overlay, command []string) (orchestrator.Plan, error) {
	plan := orchestrator.Plan{
		RepoRoot:    repoRoot,
		SandboxHome: "/home/sandbox",
		TmpDir:      tmpDir,
		Mounts:      nil,
		EnvSet: map[string]string{
			"SANDBOX_MARKER": "inside",
		},
		Overlay: overlay,
		Command: command,
	}
	return plan, nil
}

// readFileOrDie reads a file or fails the test.
func readFileOrDie(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- fixed paths in tests only
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// writeTempFile writes content to a fresh temp file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { // #nosec G304 -- keg-created dir
		t.Fatal(err)
	}
	return path
}

// mountFile returns a read-only file bind for the plan.
func mountFile(hostPath, dest string) config.Mount {
	return config.Mount{Src: hostPath, Dest: dest, Mode: config.MountRO}
}
