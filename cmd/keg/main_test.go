package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/trust"

	"github.com/urfave/cli/v3"
)

// TestMain isolates every test in this package from the developer's real
// machine user config (~/.config/keg/config.yaml). Tests that omit an
// explicit --user-config rely on BuildPlan's defaults-only behavior; without
// redirecting XDG_CONFIG_HOME a developer-local agy config (Google SNI/DNS
// domains, mounts, secrets) would leak into otherwise-plain plans and flip
// them into configured sandboxes, making results machine-dependent.
func TestMain(m *testing.M) {
	if os.Getenv("TEST_RUN_MAIN") == "1" {
		main()
		return
	}
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

func TestCLI_Version(t *testing.T) {
	cmd := NewCommand()
	if cmd.Version == "" {
		t.Fatal("expected root command Version to be set, got empty string")
	}
	if cmd.Version != Version {
		t.Fatalf("cmd.Version = %q, want %q", cmd.Version, Version)
	}
}

func TestCLI_VersionFlag(t *testing.T) {
	cmd := NewCommand()
	var out strings.Builder
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--version"}); err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if !strings.Contains(out.String(), Version) {
		t.Errorf("version output %q does not contain %q", out.String(), Version)
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

func TestCLI_RunFlagsDeclared(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		aliases []string
	}{
		{name: "publish flag with -p alias", flag: "publish", aliases: []string{"p"}},
		{name: "env flag with -e alias", flag: "env", aliases: []string{"e"}},
		{name: "var flag with -V alias", flag: "var", aliases: []string{"V"}},
		{name: "name flag with -n alias", flag: "name", aliases: []string{"n"}},
		{name: "ephemeral flag", flag: "ephemeral"},
	}
	cmd := NewCommand()
	var runCmd *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "run" {
			runCmd = c
			break
		}
	}
	if runCmd == nil {
		t.Fatal("run command not found")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range runCmd.Flags {
				names := f.Names()
				if names[0] == tt.flag {
					for _, wantAlias := range tt.aliases {
						if !slices.Contains(names, wantAlias) {
							t.Errorf("flag --%s missing alias %s (names: %v)", tt.flag, wantAlias, names)
						}
					}
					return
				}
			}
			t.Fatalf("run flag --%s not declared", tt.flag)
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

func TestCLI_StderrOnErrorWithoutVerbose(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T) (args []string)
		wantStderr string
	}{
		{
			name: "missing explicit repo config",
			setup: func(t *testing.T) []string {
				missing := filepath.Join(t.TempDir(), "nonexistent.yaml")
				return []string{"run", "--config", missing}
			},
			wantStderr: "nonexistent.yaml",
		},
		{
			name: "invalid repo yaml version",
			setup: func(t *testing.T) []string {
				dir := t.TempDir()
				cfgPath := filepath.Join(dir, ".keg.yaml")
				content := "version: \"99\"\n"
				if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				storePath := trust.DefaultTrustPath()
				_ = os.MkdirAll(filepath.Dir(storePath), 0o755)
				store, _ := trust.LoadFile(storePath)
				_, _ = trust.Approve(store, dir, []byte(content), nil)
				_ = trust.SaveFile(storePath, store)
				return []string{"run", "--repo", dir}
			},
			wantStderr: "unsupported version",
		},
		{
			name: "invalid user config",
			setup: func(t *testing.T) []string {
				dir := t.TempDir()
				userCfg := filepath.Join(dir, "user.yaml")
				if err := os.WriteFile(userCfg, []byte("invalid: yaml: ["), 0o644); err != nil {
					t.Fatal(err)
				}
				return []string{"run", "--user-config", userCfg}
			},
			wantStderr: "user config",
		},
		{
			name: "mutually exclusive flags",
			setup: func(t *testing.T) []string {
				return []string{"run", "--ephemeral", "--disk-overlay", "foo"}
			},
			wantStderr: "mutually exclusive",
		},
		{
			name: "untrusted repo config non-interactive",
			setup: func(t *testing.T) []string {
				dir := t.TempDir()
				cfgPath := filepath.Join(dir, ".keg.yaml")
				content := "version: \"1\"\n"
				if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				// Don't approve in trust store
				return []string{"run", "--repo", dir}
			},
			wantStderr: "is untrusted or has changed",
		},
		{
			name: "invalid env flag",
			setup: func(t *testing.T) []string {
				return []string{"run", "-e", "=bad"}
			},
			wantStderr: "invalid environment flag entry",
		},
		{
			name: "invalid var flag",
			setup: func(t *testing.T) []string {
				return []string{"run", "-V", "badformat"}
			},
			wantStderr: "invalid variable flag entry",
		},
		{
			name: "invalid publish port flag",
			setup: func(t *testing.T) []string {
				return []string{"run", "-p", "999999"}
			},
			wantStderr: "out of range",
		},
		{
			name: "serve invalid auth",
			setup: func(t *testing.T) []string {
				return []string{"serve", "--listen", "0.0.0.0:9999", "--auth", "none"}
			},
			wantStderr: "token auth is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.setup(t)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "TEST_RUN_MAIN=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err == nil {
				t.Fatalf("expected command to fail, but succeeded with stdout: %q", stdout.String())
			}

			stderrStr := stderr.String()
			if !strings.Contains(stderrStr, tt.wantStderr) {
				t.Fatalf("stderr %q does not contain %q", stderrStr, tt.wantStderr)
			}
			if !strings.HasPrefix(stderrStr, "keg:") {
				t.Errorf("stderr %q should start with 'keg:' prefix", stderrStr)
			}
		})
	}
}
