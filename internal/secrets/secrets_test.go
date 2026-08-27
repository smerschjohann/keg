package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/template"
)

func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFetchInitial_Success(t *testing.T) {
	script := writeScript(t, "get-token", `echo -n "secret-token-123"`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{
		{Name: "ai_token", Env: "AI_TOKEN_FILE"},
	}
	sources := map[string]config.SecretSource{
		"ai_token": {
			Cmd: []string{script},
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir); err != nil {
		t.Fatalf("FetchInitial: %v", err)
	}

	secretPath := filepath.Join(destDir, "ai_token")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if string(data) != "secret-token-123" {
		t.Errorf("secret data = %q, want %q", string(data), "secret-token-123")
	}

	// Verify permissions
	dirInfo, err := os.Stat(destDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o400 {
		t.Errorf("file mode = %o, want 0400", fileInfo.Mode().Perm())
	}
}

func TestFetchInitial_MissingSource(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "secrets")
	requested := []config.SecretRef{
		{Name: "unknown_secret"},
	}
	sources := map[string]config.SecretSource{}

	err := FetchInitial(context.Background(), requested, sources, destDir)
	if err == nil {
		t.Fatal("expected error for missing secret source, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown_secret")) {
		t.Errorf("error should name unknown_secret: %v", err)
	}
}

func TestFetchInitial_CmdFails(t *testing.T) {
	script := writeScript(t, "fail-token", `echo "vault error" >&2; exit 1`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{{Name: "ai_token"}}
	sources := map[string]config.SecretSource{
		"ai_token": {Cmd: []string{script}},
	}

	err := FetchInitial(context.Background(), requested, sources, destDir)
	if err == nil {
		t.Fatal("expected error when fetch cmd fails, got nil")
	}
}

func TestRefresher_ChangedAndUnchanged(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(stateFile, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := writeScript(t, "get-state", `cat `+stateFile)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{{Name: "dyn_secret"}}
	sources := map[string]config.SecretSource{
		"dyn_secret": {
			Cmd:      []string{script},
			Interval: config.Duration{Duration: 20 * time.Millisecond},
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir); err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		audits  []string
		changed int
	)
	auditFn := func(name, status string) {
		mu.Lock()
		defer mu.Unlock()
		audits = append(audits, name+":"+status)
		if status == "changed" {
			changed++
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, auditFn, nil)

	// Wait for an unchanged tick
	time.Sleep(50 * time.Millisecond)

	// Update state
	if err := os.WriteFile(stateFile, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for refresher to pick up change
	time.Sleep(60 * time.Millisecond)

	data, err := os.ReadFile(filepath.Join(destDir, "dyn_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "v2" {
		t.Errorf("refreshed data = %q, want v2", string(data))
	}

	mu.Lock()
	defer mu.Unlock()
	if changed < 1 {
		t.Errorf("expected at least 1 changed audit event, got: %v", audits)
	}
}

func TestRefresher_OnRefreshErrorKeep(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(stateFile, []byte("good-val"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := writeScript(t, "flaky", `
if [ -f `+stateFile+` ]; then
  cat `+stateFile+`
else
  exit 1
fi
`)
	destDir := filepath.Join(t.TempDir(), "secrets")
	requested := []config.SecretRef{{Name: "my_sec"}}
	sources := map[string]config.SecretSource{
		"my_sec": {
			Cmd:            []string{script},
			Interval:       config.Duration{Duration: 20 * time.Millisecond},
			OnRefreshError: "keep",
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir); err != nil {
		t.Fatal(err)
	}

	var (
		mu         sync.Mutex
		errorAudit bool
	)
	auditFn := func(name, status string) {
		mu.Lock()
		defer mu.Unlock()
		if status == "error" {
			errorAudit = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, auditFn, nil)

	// Make script fail
	_ = os.Remove(stateFile)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	hasErr := errorAudit
	mu.Unlock()

	if !hasErr {
		t.Error("expected error audit on refresh failure")
	}

	// Secret file must still exist and keep good value
	data, err := os.ReadFile(filepath.Join(destDir, "my_sec"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "good-val" {
		t.Errorf("kept secret = %q, want good-val", string(data))
	}
}

func TestRefresher_OnRefreshErrorFail(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(stateFile, []byte("good-val"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := writeScript(t, "flaky2", `
if [ -f `+stateFile+` ]; then
  cat `+stateFile+`
else
  exit 1
fi
`)
	destDir := filepath.Join(t.TempDir(), "secrets")
	requested := []config.SecretRef{{Name: "fail_sec"}}
	sources := map[string]config.SecretSource{
		"fail_sec": {
			Cmd:            []string{script},
			Interval:       config.Duration{Duration: 20 * time.Millisecond},
			OnRefreshError: "fail",
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir); err != nil {
		t.Fatal(err)
	}

	var fatalCalled atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, nil, func(err error) {
		fatalCalled.Store(true)
	})

	_ = os.Remove(stateFile)
	time.Sleep(60 * time.Millisecond)

	if !fatalCalled.Load() {
		t.Error("expected onFatalError to be called when on_refresh_error: fail")
	}
}

func TestFetchInitial_TemplateExpansion(t *testing.T) {
	script := writeScript(t, "echo-args", `echo -n "$1 $2 $3"`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{
		{Name: "ai_token"},
	}
	sources := map[string]config.SecretSource{
		"ai_token": {
			Cmd: []string{
				script,
				"{{ .Vars.instance }}",
				`{{ .Vars.token_ttl | default "1500" }}`,
				"{{ .Vars.secret_name }}",
			},
		},
	}

	tctx := template.Context{
		Vars: map[string]string{
			"instance":  "my-sandbox",
			"token_ttl": "1800",
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir, tctx); err != nil {
		t.Fatalf("FetchInitial: %v", err)
	}

	secretPath := filepath.Join(destDir, "ai_token")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	want := "my-sandbox 1800 ai_token"
	if string(data) != want {
		t.Errorf("secret data = %q, want %q", string(data), want)
	}
}

func TestFetchInitial_SubprocessEnvironment(t *testing.T) {
	script := writeScript(t, "echo-env", `echo -n "$KEG_INSTANCE $KEG_SECRET_NAME $KEG_REPO_DIR"`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{
		{Name: "ai_key"},
	}
	sources := map[string]config.SecretSource{
		"ai_key": {
			Cmd: []string{script},
		},
	}

	tctx := template.Context{
		Vars: map[string]string{
			"instance": "test-box-42",
			"repo_dir": "/home/dev/repo",
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir, tctx); err != nil {
		t.Fatalf("FetchInitial: %v", err)
	}

	secretPath := filepath.Join(destDir, "ai_key")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	want := "test-box-42 ai_key /home/dev/repo"
	if string(data) != want {
		t.Errorf("secret data = %q, want %q", string(data), want)
	}
}

func TestRefresher_TemplateExpansion(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "val.txt")
	if err := os.WriteFile(stateFile, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := writeScript(t, "refresh-echo", `echo -n "$(cat `+stateFile+`) $1 $KEG_INSTANCE"`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{{Name: "dyn_sec"}}
	sources := map[string]config.SecretSource{
		"dyn_sec": {
			Cmd:      []string{script, "{{ .Vars.token_ttl }}"},
			Interval: config.Duration{Duration: 20 * time.Millisecond},
		},
	}

	tctx := template.Context{
		Vars: map[string]string{
			"instance":  "my-inst",
			"token_ttl": "900",
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir, tctx); err != nil {
		t.Fatal(err)
	}

	initialData, _ := os.ReadFile(filepath.Join(destDir, "dyn_sec"))
	if string(initialData) != "v1 900 my-inst" {
		t.Fatalf("initial = %q, want 'v1 900 my-inst'", string(initialData))
	}

	var changedAudit atomic.Bool
	auditFn := func(name, status string) {
		if status == "changed" {
			changedAudit.Store(true)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, auditFn, nil, tctx)

	// Update state
	_ = os.WriteFile(stateFile, []byte("v2"), 0o600)

	deadline := time.Now().Add(2 * time.Second)
	var lastData string
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		data, err := os.ReadFile(filepath.Join(destDir, "dyn_sec"))
		if err == nil {
			lastData = string(data)
			if lastData == "v2 900 my-inst" {
				break
			}
		}
	}

	if !changedAudit.Load() {
		t.Error("expected changed audit after refresher ran")
	}

	if lastData != "v2 900 my-inst" {
		t.Errorf("refreshed = %q, want 'v2 900 my-inst'", lastData)
	}
}

func TestFetchInitial_AsyncSkipped(t *testing.T) {
	script := writeScript(t, "get-token-fail", `echo "should not be called" >&2; exit 1`)
	destDir := filepath.Join(t.TempDir(), "secrets")

	requested := []config.SecretRef{
		{Name: "async_token"},
	}
	sources := map[string]config.SecretSource{
		"async_token": {
			Cmd:   []string{script},
			Async: true,
		},
	}

	if err := FetchInitial(context.Background(), requested, sources, destDir); err != nil {
		t.Fatalf("FetchInitial with async source must not fail: %v", err)
	}

	secretPath := filepath.Join(destDir, "async_token")
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Errorf("secret file %s should not exist after FetchInitial with Async=true", secretPath)
	}
}

func TestRefresher_AsyncInitialFetch(t *testing.T) {
	script := writeScript(t, "get-async-token", `echo -n "async-secret-val"`)
	destDir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		t.Fatal(err)
	}

	requested := []config.SecretRef{{Name: "async_token"}}
	sources := map[string]config.SecretSource{
		"async_token": {
			Cmd:   []string{script},
			Async: true,
		},
	}

	var changedAudit atomic.Bool
	auditFn := func(name, status string) {
		if status == "changed" {
			changedAudit.Store(true)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, auditFn, nil)

	deadline := time.Now().Add(2 * time.Second)
	var gotData string
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		data, err := os.ReadFile(filepath.Join(destDir, "async_token"))
		if err == nil {
			gotData = string(data)
			if gotData == "async-secret-val" {
				break
			}
		}
	}

	if gotData != "async-secret-val" {
		t.Errorf("async secret content = %q, want 'async-secret-val'", gotData)
	}
	if !changedAudit.Load() {
		t.Error("expected changed audit after async initial fetch")
	}
}

func TestRefresher_AsyncWithInterval(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.txt")
	if err := os.WriteFile(stateFile, []byte("val1"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := writeScript(t, "get-async-dyn", `cat `+stateFile)
	destDir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		t.Fatal(err)
	}

	requested := []config.SecretRef{{Name: "async_dyn"}}
	sources := map[string]config.SecretSource{
		"async_dyn": {
			Cmd:      []string{script},
			Async:    true,
			Interval: config.Duration{Duration: 30 * time.Millisecond},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := NewRefresher()
	go refresher.Start(ctx, requested, sources, destDir, nil, nil)

	// Verify initial async fetch
	deadline := time.Now().Add(2 * time.Second)
	var gotData string
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		data, err := os.ReadFile(filepath.Join(destDir, "async_dyn"))
		if err == nil {
			gotData = string(data)
			if gotData == "val1" {
				break
			}
		}
	}
	if gotData != "val1" {
		t.Fatalf("initial async data = %q, want 'val1'", gotData)
	}

	// Update state and verify periodic refresh
	_ = os.WriteFile(stateFile, []byte("val2"), 0o600)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		data, err := os.ReadFile(filepath.Join(destDir, "async_dyn"))
		if err == nil {
			gotData = string(data)
			if gotData == "val2" {
				break
			}
		}
	}
	if gotData != "val2" {
		t.Errorf("refreshed async data = %q, want 'val2'", gotData)
	}
}
