package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/frame"
	"github.com/smerschjohann/keg/internal/trust"
)

func writeRepoConfig(t *testing.T, dir string) {
	t.Helper()
	content := []byte("version: \"1\"\n")
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	storePath := trust.DefaultTrustPath()
	store, _ := trust.LoadFile(storePath)
	_, _ = trust.Approve(store, dir, content)
	_ = trust.SaveFile(storePath, store)
}

func sendRequest(t *testing.T, conn net.Conn, req Request) Response {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	if err := frame.WriteFrame(conn, data); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	resData, err := frame.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var res Response
	if err := json.Unmarshal(resData, &res); err != nil {
		t.Fatalf("unmarshal res: %v", err)
	}
	return res
}

func TestDaemon_NetworkRequiresAuth(t *testing.T) {
	// TCP listener on 0.0.0.0 or non-loopback without token must fail immediately
	cfg := Config{
		ListenAddr: "0.0.0.0:8888",
		Auth:       "none",
	}
	srv, err := NewServer(cfg)
	if err == nil {
		_ = srv.Close()
		t.Fatal("expected error when binding to network without auth token, got nil")
	}
	if !strings.Contains(err.Error(), "token auth is required") {
		t.Errorf("error = %q, want token auth is required", err.Error())
	}
}

func TestDaemon_UnixSocketAndLifecycle(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "api.sock")

	repoDir := t.TempDir()
	writeRepoConfig(t, repoDir)

	srv, err := NewServer(Config{
		ListenAddr:   "unix://" + sockPath,
		Auth:         "token",
		Token:        "secret-pass",
		MaxSandboxes: 2,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)

	// Check socket file permissions (0660)
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode()&0o777 != 0o660 {
		t.Errorf("socket permissions = %o, want 0660", info.Mode()&0o777)
	}

	// 1. Connect without auth / wrong auth -> rejected
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	unauthRes := sendRequest(t, conn, Request{
		Action: ActionCreate,
		Token:  "wrong-token",
	})
	if unauthRes.Success {
		t.Error("expected authentication failure, got success")
	}

	// 2. Create sandbox
	createRes := sendRequest(t, conn, Request{
		Action:   ActionCreate,
		Token:    "secret-pass",
		RepoRoot: repoDir,
		Options: LaunchOptions{
			Ephemeral: true,
		},
	})
	if !createRes.Success {
		t.Fatalf("create failed: %s", createRes.Error)
	}
	sbID := createRes.SandboxID
	if sbID == "" {
		t.Fatal("empty SandboxID")
	}

	// 3. Status
	statusRes := sendRequest(t, conn, Request{
		Action:    ActionStatus,
		Token:     "secret-pass",
		SandboxID: sbID,
	})
	if !statusRes.Success || statusRes.Status != "running" {
		t.Errorf("status = %+v, want running", statusRes)
	}

	// 4. List
	listRes := sendRequest(t, conn, Request{
		Action: ActionList,
		Token:  "secret-pass",
	})
	if !listRes.Success || len(listRes.Sandboxes) != 1 {
		t.Errorf("list = %+v, want 1 sandbox", listRes)
	}

	// 5. Stop
	stopRes := sendRequest(t, conn, Request{
		Action:    ActionStop,
		Token:     "secret-pass",
		SandboxID: sbID,
	})
	if !stopRes.Success {
		t.Errorf("stop failed: %s", stopRes.Error)
	}

	// 6. List after stop
	listAfterRes := sendRequest(t, conn, Request{
		Action: ActionList,
		Token:  "secret-pass",
	})
	if !listAfterRes.Success || len(listAfterRes.Sandboxes) != 0 {
		t.Errorf("list after stop = %+v, want 0 sandboxes", listAfterRes)
	}
}

func TestDaemon_MaxSandboxesLimit(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "api.sock")

	repoDir := t.TempDir()
	writeRepoConfig(t, repoDir)

	srv, err := NewServer(Config{
		ListenAddr:   "unix://" + sockPath,
		Auth:         "none",
		MaxSandboxes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 1. Create first sandbox -> ok
	res1 := sendRequest(t, conn, Request{
		Action:   ActionCreate,
		RepoRoot: repoDir,
		Options:  LaunchOptions{Ephemeral: true},
	})
	if !res1.Success {
		t.Fatalf("first create failed: %s", res1.Error)
	}

	// 2. Create second sandbox -> rejected by limit
	res2 := sendRequest(t, conn, Request{
		Action:   ActionCreate,
		RepoRoot: repoDir,
		Options:  LaunchOptions{Ephemeral: true},
	})
	if res2.Success || !strings.Contains(res2.Error, "maximum sandbox limit") {
		t.Errorf("expected max limit error, got: %+v", res2)
	}
}

func TestDaemon_Exec(t *testing.T) {
	if _, err := os.Stat("/usr/bin/bwrap"); err != nil {
		t.Skip("bwrap not available, skipping Exec test")
	}

	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "api.sock")

	repoDir := t.TempDir()
	writeRepoConfig(t, repoDir)

	srv, err := NewServer(Config{
		ListenAddr:   "unix://" + sockPath,
		Auth:         "none",
		MaxSandboxes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	createRes := sendRequest(t, conn, Request{
		Action:   ActionCreate,
		RepoRoot: repoDir,
		Options: LaunchOptions{
			Ephemeral: true,
			Command:   []string{"/bin/sh", "-c", "echo hello-from-daemon"},
		},
	})
	if !createRes.Success {
		t.Fatalf("create failed: %s", createRes.Error)
	}

	// Exec request
	reqData, _ := json.Marshal(Request{
		Action:    ActionExec,
		SandboxID: createRes.SandboxID,
		Argv:      []string{"/bin/sh", "-c", "echo executed-command"},
	})
	if err := frame.WriteFrame(conn, reqData); err != nil {
		t.Fatal(err)
	}

	// Read events until exit
	var stdoutOutput string
	for {
		data, err := frame.ReadFrame(conn)
		if err != nil {
			break
		}
		var ev ExecEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if ev.Type == "stdout" {
			raw, _ := base64.StdEncoding.DecodeString(ev.Data)
			stdoutOutput += string(raw)
		}
		if ev.Type == "exit" {
			if ev.Code != 0 {
				t.Errorf("exit code = %d, want 0", ev.Code)
			}
			break
		}
	}
	if !strings.Contains(stdoutOutput, "executed-command") {
		t.Errorf("stdout = %q, want 'executed-command'", stdoutOutput)
	}
}
