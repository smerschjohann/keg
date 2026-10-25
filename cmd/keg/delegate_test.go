package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/runner"

	"golang.ngrok.com/muxado"
)

// fakeRunnerDaemon mirrors the production topology of delegation channel C:
// ServeSession over a muxado session whose peer is fed by a Bridge accepting
// workload connections on a unix socket at sockPath (guest.go wires exactly
// this for fd FDRunner).
func fakeRunnerDaemon(t *testing.T, sockPath string, cfg runner.ServerConfig) {
	t.Helper()
	fa, fb := unixSocketpair()
	hostSess := muxado.Server(fa, nil)
	guestSess := muxado.Client(fb, nil)
	t.Cleanup(func() {
		_ = hostSess.Close()
		_ = guestSess.Close()
	})
	go func() { _ = runner.ServeSession(hostSess, cfg) }()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("fake daemon listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = runner.Bridge(ctx, guestSess, ln) }()
}

// unixSocketpair returns the ends of an AF_UNIX socketpair as generic conns.
func unixSocketpair() (a, b net.Conn) {
	fds, err0 := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err0 != nil {
		panic(err0)
	}
	fa := os.NewFile(uintptr(fds[0]), "a")
	fb := os.NewFile(uintptr(fds[1]), "b")
	a, e1 := net.FileConn(fa)
	b, e2 := net.FileConn(fb)
	if e1 != nil || e2 != nil {
		panic("socketpair fileconn")
	}
	return a, b
}

// writeScriptFile creates an executable shell script at path.
func writeScriptFile(t *testing.T, path, body string) string {
	t.Helper()
	content := "#!/bin/sh\n" + body
	if err := os.WriteFile(path, []byte(content), 0o750); err != nil { // #nosec G306 -- test fixture
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func TestDelegateAction_ExitCodesAndOutput(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "runner.sock")
	prev := runner.SocketPath
	runner.SocketPath = sockPath
	t.Cleanup(func() { runner.SocketPath = prev })

	engine, err := runner.NewEngine(config.DelegatedTasks{Exact: []string{"ok"}}, config.RunnerCfg{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	repo := t.TempDir()
	fakeRunnerDaemon(t, sockPath, runner.ServerConfig{
		Engine:   engine,
		JustBin:  writeScriptFile(t, filepath.Join(repo, "just"), "echo ran:$1\n"),
		RepoRoot: repo,
	})

	tests := []struct {
		name     string
		argv     []string
		wantCode int
	}{
		{"whitelisted job", []string{"ok"}, 0},
		{"denied job", []string{"nope"}, runner.CodeRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := delegateAction(tt.argv)
			if code != tt.wantCode {
				t.Fatalf("delegateAction(%v) = %d, want %d", tt.argv, code, tt.wantCode)
			}
		})
	}

	// Missing socket ⇒ 127; "no delegated_tasks configured" is the normal case.
	runner.SocketPath = filepath.Join(t.TempDir(), "missing.sock")
	if code := delegateAction([]string{"ok"}); code != runner.CodeNoRunner {
		t.Fatalf("missing socket: code = %d, want %d", code, runner.CodeNoRunner)
		t.Fatalf("missing socket: code = %d, want %d", code, runner.CodeNoRunner)
	}
}

func TestCLI_DelegateCommandExists(t *testing.T) {
	cmd := NewCommand()
	for _, c := range cmd.Commands {
		if c.HasName("delegate") {
			return
		}
	}
	t.Fatal("command \"delegate\" not found")
}

func TestDelegateList_ViaRunnerSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "runner.sock")
	prev := runner.SocketPath
	runner.SocketPath = sockPath
	t.Cleanup(func() { runner.SocketPath = prev })

	repo := t.TempDir()
	justContent := `
# Build the container image on the host
container-build:
	podman build .

# Run Playwright E2E tests
test-playwright *args:
	npx playwright test "$@"
`
	if err := os.WriteFile(filepath.Join(repo, "justfile"), []byte(justContent), 0o600); err != nil {
		t.Fatal(err)
	}

	engine, err := runner.NewEngine(
		config.DelegatedTasks{
			Exact:    []string{"container-build"},
			Prefixes: []string{"test-playwright"},
			Raw: []config.RawRule{{
				Cmd:         "git",
				Description: "Run safe local git commands",
				Subcommands: []string{"status", "diff"},
			}},
		},
		config.RunnerCfg{
			ExtraExact: []string{"host-extra"},
			Descriptions: map[string]string{
				"host-extra": "Extra host task from user config",
			},
		},
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.SetFallbackDescriptions(config.DiscoverJustfileDescriptions(repo))

	fakeRunnerDaemon(t, sockPath, runner.ServerConfig{
		Engine:   engine,
		RepoRoot: repo,
	})

	var out, errBuf bytes.Buffer
	code := delegateActionWithIO([]string{"--list"}, "", "", "", &out, &errBuf)
	if code != 0 {
		t.Fatalf("delegateActionWithIO(--list) = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	got := out.String()
	for _, want := range []string{
		"container-build",
		"Build the container image on the host",
		"test-playwright",
		"Run Playwright E2E tests",
		"host-extra",
		"Extra host task from user config",
		"git",
		"Run safe local git commands",
		"status, diff",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--list output missing %q:\n%s", want, got)
		}
	}

	// Also verify --json output
	out.Reset()
	errBuf.Reset()
	code = delegateActionWithIO([]string{"--list", "--json"}, "", "", "", &out, &errBuf)
	if code != 0 {
		t.Fatalf("delegateActionWithIO(--list --json) = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"name": "container-build"`) {
		t.Errorf("--list --json output missing JSON task entry:\n%s", out.String())
	}
}

func TestDelegateList_HostFallbackWithoutSocket(t *testing.T) {
	// Point SocketPath at a non-existent socket so delegate --list falls back to host config loading.
	prev := runner.SocketPath
	runner.SocketPath = filepath.Join(t.TempDir(), "absent.sock")
	t.Cleanup(func() { runner.SocketPath = prev })

	repo := t.TempDir()
	repoYAML := `version: "1"
delegated_tasks:
  exact:
    - name: container-build
      description: "YAML description for container-build"
    - from-justfile
  raw:
    - cmd: git
      description: "Git on host"
      subcommands: [status]
`
	if err := os.WriteFile(filepath.Join(repo, ".keg.yaml"), []byte(repoYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	justContent := `
# Comment from justfile for container-build
container-build:
	echo build

# Description extracted from justfile
from-justfile:
	echo just
`
	if err := os.WriteFile(filepath.Join(repo, "justfile"), []byte(justContent), 0o600); err != nil {
		t.Fatal(err)
	}

	userCfgPath := filepath.Join(t.TempDir(), "config.yaml")
	userYAML := `runner:
  extra_prefixes:
    - name: agy
      description: "Run agy on host"
`
	if err := os.WriteFile(userCfgPath, []byte(userYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := delegateActionWithIO([]string{"--list"}, repo, "", userCfgPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("host fallback --list code = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	got := out.String()
	for _, want := range []string{
		"container-build",
		"YAML description for container-build",
		"from-justfile",
		"Description extracted from justfile",
		"agy",
		"Run agy on host",
		"git",
		"Git on host",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("host fallback --list output missing %q:\n%s", want, got)
		}
	}
}
