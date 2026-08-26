package runner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"

	"golang.ngrok.com/muxado"
)

func TestBridge_EndToEndClientThroughSocket(t *testing.T) {
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "runner.sock")

	engine, err := NewEngine(config.DelegatedTasks{}, config.RunnerCfg{
		ExtraExact:    []string{"hello"},
		ExtraPrefixes: []string{"greet"},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := ServerConfig{
		Engine:   engine,
		JustBin:  writeScript(t, "just", `echo "hi:$*"; echo err-line >&2; exit ${FAKE_EXIT:-0}`),
		RepoRoot: tmp,
	}

	guestEnd, hostEnd := socketpairTCP(t)
	serverSess := muxado.Server(hostEnd, nil)
	clientSess := muxado.Client(guestEnd, nil)
	t.Cleanup(func() {
		_ = serverSess.Close()
		_ = clientSess.Close()
	})
	go func() { _ = ServeSession(serverSess, cfg) }()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen %s: %v", sockPath, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Bridge(ctx, clientSess, ln) }()

	// The workload connects to the filesystem socket exactly like
	// `just delegate` would.
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var out, errBuf strings.Builder
	code := Exec(conn, []string{"greet", "world"}, "", &out, &errBuf)
	if code != 0 {
		t.Fatalf("Exec = %d (stderr %q)", code, errBuf.String())
	}
	if out.String() != "hi:greet world\n" {
		t.Errorf("stdout = %q", out.String())
	}

	// Cancel tears the bridge down; dangling connections don't block it.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge did not stop after context cancel")
	}
	if _, statErr := os.Stat(sockPath); statErr == nil {
		_ = os.Remove(sockPath) // best effort cleanup after failed run
	}
}
