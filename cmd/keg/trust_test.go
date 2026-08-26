package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/trust"
)

func TestTrustCommand_Set_Revoke_Status(t *testing.T) {
	tempDir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", trustDir)

	repoDir := filepath.Join(tempDir, "myrepo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(repoDir, ".keg.yaml")
	cfgContent := "version: \"1\"\nenv:\n  inherit:\n    - LANG\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, _ := trust.Sha256([]byte(cfgContent))

	// 1. Initially status is NONE (not approved)
	cmd := NewCommand()
	var out bytes.Buffer
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir, "--status"}); err != nil {
		t.Fatalf("trust --status failed: %v", err)
	}
	if !strings.Contains(out.String(), "NONE") || !strings.Contains(out.String(), sha) {
		t.Errorf("expected NONE and checksum %s, got:\n%s", sha, out.String())
	}

	// 2. Run `keg trust --repo <path>` -> sets approved
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir}); err != nil {
		t.Fatalf("keg trust failed: %v", err)
	}
	if !strings.Contains(out.String(), sha) {
		t.Errorf("trust output should contain checksum %s, got:\n%s", sha, out.String())
	}

	// 3. Status is now TRUSTED
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir, "--status"}); err != nil {
		t.Fatalf("trust --status failed: %v", err)
	}
	if !strings.Contains(out.String(), "TRUSTED") || !strings.Contains(out.String(), sha) {
		t.Errorf("expected TRUSTED and checksum %s, got:\n%s", sha, out.String())
	}

	// 4. Modify config file -> status becomes CHANGED
	newContent := "version: \"1\"\nenv:\n  inherit:\n    - LANG\n    - TERM\n"
	if err := os.WriteFile(cfgPath, []byte(newContent), 0o600); err != nil {
		t.Fatal(err)
	}
	newSha, _ := trust.Sha256([]byte(newContent))

	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir, "--status"}); err != nil {
		t.Fatalf("trust --status on changed file failed: %v", err)
	}
	if !strings.Contains(out.String(), "CHANGED") || !strings.Contains(out.String(), newSha) {
		t.Errorf("expected CHANGED and checksum %s, got:\n%s", newSha, out.String())
	}

	// 5. Revoke -> status is NONE
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir, "--revoke"}); err != nil {
		t.Fatalf("trust --revoke failed: %v", err)
	}

	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--repo", repoDir, "--status"}); err != nil {
		t.Fatalf("trust --status after revoke failed: %v", err)
	}
	if !strings.Contains(out.String(), "NONE") {
		t.Errorf("expected NONE after revoke, got:\n%s", out.String())
	}
}

func TestCLI_HelpIncludesTrustAndEnvFlags(t *testing.T) {
	cmd := NewCommand()
	var out strings.Builder
	cmd.Writer = &out

	// 1. run --help
	if err := cmd.Run(context.Background(), []string{"keg", "run", "--help"}); err != nil {
		t.Fatalf("run --help failed: %v", err)
	}
	runHelp := out.String()
	for _, want := range []string{"--env", "-e", "--inherit-all"} {
		if !strings.Contains(runHelp, want) {
			t.Errorf("run --help missing %q", want)
		}
	}

	// 2. trust --help
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "trust", "--help"}); err != nil {
		t.Fatalf("trust --help failed: %v", err)
	}
	trustHelp := out.String()
	for _, want := range []string{"--repo", "--revoke", "--status"} {
		if !strings.Contains(trustHelp, want) {
			t.Errorf("trust --help missing %q", want)
		}
	}
}
