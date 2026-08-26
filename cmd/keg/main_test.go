package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// TestMain isolates every test in this package from the developer's real
// machine user config (~/.config/keg/config.yaml). Tests that omit an
// explicit --user-config rely on BuildPlan's defaults-only behavior; without
// redirecting XDG_CONFIG_HOME a developer-local agy config (Google SNI/DNS
// domains, mounts, secrets) would leak into otherwise-plain plans and flip
// them into configured sandboxes, making results machine-dependent.
func TestMain(m *testing.M) {
	if orchestrator.InitGuestDispatch() {
		return
	}
	dir, err := os.MkdirTemp("", "keg-test-userconfig")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: create temp user config dir:", err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: set XDG_CONFIG_HOME:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// runCLI executes the root command with the given arguments, mirroring an
// actual CLI invocation without spawning a process.
func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	return NewCommand().Run(context.Background(), append([]string{"keg"}, args...))
}

func TestCLI_CommandsExist(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "run", command: "run"},
		{name: "run alias r", command: "r"},
		{name: "trust", command: "trust"},
		{name: "agent", command: "agent"},
		{name: "list", command: "list"},
		{name: "clean", command: "clean"},
		{name: "clean-cache", command: "clean-cache"},
		{name: "serve", command: "serve"},
	}
	cmd := NewCommand()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range cmd.Commands {
				if c.HasName(tt.command) {
					return
				}
			}
			t.Fatalf("command %q not found", tt.command)
		})
	}
}

func TestCLI_GlobalFlagsDeclared(t *testing.T) {
	tests := []struct {
		name string
		flag string
	}{
		{name: "config", flag: "config"},
		{name: "user-config", flag: "user-config"},
		{name: "verbose", flag: "verbose"},
	}
	cmd := NewCommand()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range cmd.Flags {
				if f.Names()[0] == tt.flag {
					return
				}
			}
			t.Fatalf("global flag --%s not declared", tt.flag)
		})
	}
}

func TestCLI_HelpListsSubcommandsWithUsage(t *testing.T) {
	cmd := NewCommand()
	var out strings.Builder
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--help"}); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	help := out.String()
	for _, want := range []string{
		"isolated development sandbox",
		"start a sandbox and run a command inside it",
		"manage repository configuration trust",
		"agent helpers for repository setup",
		"list persistent overlay layers",
		"delete a persistent overlay layer",
		"remote-control daemon",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help output missing %q", want)
		}
	}
}

func TestCLI_ListAndClean(t *testing.T) {
	storageBase := t.TempDir()
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	if err := os.WriteFile(userCfg, []byte("paths:\n  storage_base: "+storageBase+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Initially empty
	cmd := NewCommand()
	var out strings.Builder
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--user-config", userCfg, "list"}); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(out.String(), "No persistent layers found") {
		t.Errorf("empty list output = %q, want 'No persistent layers found'", out.String())
	}

	// 2. Create repo layer "agent-1" and cache layer "cache-mycache"
	if err := os.MkdirAll(filepath.Join(storageBase, "agent-1", "rw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storageBase, "agent-1", "rw", "data.txt"), []byte("agent data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(storageBase, "cache-mycache", "mod-rw"), 0o755); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--user-config", userCfg, "list"}); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	listOut := out.String()
	if !strings.Contains(listOut, "agent-1") || !strings.Contains(listOut, "mycache") {
		t.Errorf("list output missing layers: %s", listOut)
	}

	// 3. Clean specific repo layer
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--user-config", userCfg, "clean", "agent-1"}); err != nil {
		t.Fatalf("clean failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(storageBase, "agent-1")); !os.IsNotExist(err) {
		t.Error("agent-1 should be deleted")
	}

	// 4. Clean cache layer
	out.Reset()
	cmd = NewCommand()
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--user-config", userCfg, "clean-cache", "mycache"}); err != nil {
		t.Fatalf("clean-cache failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(storageBase, "cache-mycache")); !os.IsNotExist(err) {
		t.Error("cache-mycache should be deleted")
	}
}

func TestCLI_CleanErrors(t *testing.T) {
	storageBase := t.TempDir()
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	if err := os.WriteFile(userCfg, []byte("paths:\n  storage_base: "+storageBase+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// clean without name
	err := runCLI(t, "--user-config", userCfg, "clean")
	if err == nil || !strings.Contains(err.Error(), "clean requires a layer NAME or --all") {
		t.Errorf("clean without name should fail, got: %v", err)
	}

	// clean non-existent layer
	err = runCLI(t, "--user-config", userCfg, "clean", "non-existent")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("clean non-existent should fail, got: %v", err)
	}
}

func TestCLI_RunWithoutConfigFailsWithClearError(t *testing.T) {
	// Since c10a3a4 ("allow without repo config") `run` in a directory
	// WITHOUT .keg.yaml falls back to default settings — it must NOT
	// be invoked here for real: inside `go test`, Launch would re-exec
	// THIS test binary as sandbox guest (/proc/self/exe), recursing
	// through the whole suite forever.
	//
	// Hard CLI failure contract stays pinned via an explicit --config
	// path: BuildPlan errors before any process is spawned.
	dir := t.TempDir()
	err := runCLI(t, "--config", filepath.Join(dir, "absent-config.yaml"), "run", "--repo", dir)
	if err == nil || !strings.Contains(err.Error(), "absent-config.yaml") {
		t.Fatalf("explicit missing --config must fail naming the file, got: %v", err)
	}
}

func TestCLI_RunOverlayFlagsMutualExclusivity(t *testing.T) {
	t.Run("ephemeral and disk-overlay mutually exclusive", func(t *testing.T) {
		err := runCLI(t, "run", "--ephemeral", "--disk-overlay", "foo")
		if err == nil || !strings.Contains(err.Error(), "--ephemeral and --disk-overlay are mutually exclusive") {
			t.Errorf("expected mutual exclusivity error, got %v", err)
		}
	})
	t.Run("isolate-caches and isolated-cache-name mutually exclusive", func(t *testing.T) {
		err := runCLI(t, "run", "--isolate-caches", "--isolated-cache-name", "foo")
		if err == nil || !strings.Contains(err.Error(), "--isolate-caches and --isolated-cache-name are mutually exclusive") {
			t.Errorf("expected mutual exclusivity error, got %v", err)
		}
	})
}

func TestCLI_ServeValidation(t *testing.T) {
	// Network listener without token auth must fail
	err := runCLI(t, "serve", "--listen", "0.0.0.0:9999", "--auth", "none")
	if err == nil || !strings.Contains(err.Error(), "token auth is required") {
		t.Errorf("expected network token auth refusal, got: %v", err)
	}
}
