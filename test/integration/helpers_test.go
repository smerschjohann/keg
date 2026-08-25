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
	findBwrap(t)
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(repoConfig), 0o644); err != nil {
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

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
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
