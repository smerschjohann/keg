package keg

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPublicAPI_OptionsAndDefaults(t *testing.T) {
	repoDir := t.TempDir()
	writeFile(t, filepath.Join(repoDir, ".keg.yaml"))

	var stdout, stderr bytes.Buffer
	var stdin bytes.Buffer

	opts := []Option{
		WithEphemeral(),
		WithName("test-instance"),
		WithStdout(&stdout),
		WithStderr(&stderr),
		WithStdin(&stdin),
		WithCommand("/bin/echo", "hello-api"),
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}

	if !cfg.ephemeral {
		t.Error("ephemeral should be true")
	}
	if cfg.instanceName != "test-instance" {
		t.Errorf("instanceName = %q, want 'test-instance'", cfg.instanceName)
	}
	if len(cfg.command) != 2 || cfg.command[0] != "/bin/echo" {
		t.Errorf("command = %v, want [/bin/echo, hello-api]", cfg.command)
	}
}

func TestPublicAPI_SecretPath(t *testing.T) {
	sb := &Sandbox{}
	if path := sb.SecretPath("ai_token"); path != "/run/secrets/ai_token" {
		t.Errorf("SecretPath = %q, want /run/secrets/ai_token", path)
	}
}

func TestPublicAPI_LaunchContextCancel(t *testing.T) {
	repoDir := t.TempDir()
	writeFile(t, filepath.Join(repoDir, ".keg.yaml"))

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately before launch or during launch
	cancel()

	_, err := Launch(ctx, repoDir, WithCommand("/bin/sleep", "10"))
	if err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestPublicAPI_ValidationErrors(t *testing.T) {
	// Missing .keg.yaml
	emptyDir := t.TempDir()
	_, err := Launch(context.Background(), emptyDir)
	if err == nil {
		t.Fatal("expected error for missing .keg.yaml, got nil")
	}

	// Mutually exclusive overlay flags
	repoDir := t.TempDir()
	writeFile(t, filepath.Join(repoDir, ".keg.yaml"))
	_, err = Launch(context.Background(), repoDir, WithEphemeral(), WithDiskOverlay("my-layer"))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got: %v", err)
	}
}

func TestPublicAPI_LifecycleAndOutput(t *testing.T) {
	// If bwrap is not available, skip test with message
	if _, err := os.Stat("/usr/bin/bwrap"); err != nil {
		t.Skip("bwrap not installed, skipping lifecycle test")
	}

	repoDir := t.TempDir()
	writeFile(t, filepath.Join(repoDir, ".keg.yaml"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sb, err := Launch(ctx, repoDir, WithEphemeral(), WithCommand("/bin/sh", "-c", "echo api-stdout; echo api-stderr >&2"))
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer sb.Close()

	if sb.Pid() <= 0 {
		t.Errorf("Pid = %d, want > 0", sb.Pid())
	}

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}
