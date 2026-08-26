package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
