//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/secrets"
)

// TestSandboxSecrets proves that secrets fetched by the host are bound into
// the sandbox under /run/secrets as read-only, that environment variables
// (e.g. AI_TOKEN_FILE=/run/secrets/ai_token) point to them, and that dynamic
// updates on the host propagate into the running sandbox.
func TestSandboxSecrets(t *testing.T) {
	dir := t.TempDir()
	findBwrap(t)
	writeFile(t, filepath.Join(dir, ".keg.yaml"), repoConfig)

	stateFile := filepath.Join(t.TempDir(), "token-state.txt")
	writeFile(t, stateFile, "initial-token-value")

	script := filepath.Join(t.TempDir(), "fetch-token")
	writeFile(t, script, "#!/bin/sh\ncat "+stateFile)
	_ = os.Chmod(script, 0o750)

	secretDir := filepath.Join(t.TempDir(), "secrets")
	requested := []config.SecretRef{
		{Name: "ai_token", Env: "AI_TOKEN_FILE"},
	}
	sources := map[string]config.SecretSource{
		"ai_token": {
			Cmd:      []string{script},
			Interval: config.Duration{Duration: 20 * time.Millisecond},
		},
	}

	if err := secrets.FetchInitial(context.Background(), requested, sources, secretDir); err != nil {
		t.Fatalf("FetchInitial: %v", err)
	}

	var out bytes.Buffer
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain, []string{
		"/bin/sh", "-c",
		`cat "$AI_TOKEN_FILE" && echo "---" && while [ "$(cat /run/secrets/ai_token)" = "initial-token-value" ]; do sleep 0.02; done && cat /run/secrets/ai_token`,
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.SecretDir = secretDir
	plan.Secrets = requested
	plan.SecretSources = sources
	plan.EnvSet["AI_TOKEN_FILE"] = "/run/secrets/ai_token"
	plan.Stdout = &out
	plan.Stderr = &out

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := secrets.NewRefresher()
	go refresher.Start(ctx, requested, sources, secretDir, nil, nil)

	sb, err := orchestrator.Launch(ctx, plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()

	// Update host state file while sandbox is running
	time.Sleep(30 * time.Millisecond)
	writeFile(t, stateFile, "refreshed-token-value")

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}

	parts := strings.Split(strings.TrimSpace(out.String()), "---")
	if len(parts) != 2 {
		t.Fatalf("unexpected output format:\n%s", out.String())
	}
	firstRead := strings.TrimSpace(parts[0])
	secondRead := strings.TrimSpace(parts[1])

	if firstRead != "initial-token-value" {
		t.Errorf("initial read = %q, want 'initial-token-value'", firstRead)
	}
	if secondRead != "refreshed-token-value" {
		t.Errorf("second read = %q, want 'refreshed-token-value'", secondRead)
	}
}

// TestSandboxSecretsReadOnly verifies that /run/secrets inside the sandbox is
// strictly read-only.
func TestSandboxSecretsReadOnly(t *testing.T) {
	dir := t.TempDir()
	findBwrap(t)
	writeFile(t, filepath.Join(dir, ".keg.yaml"), repoConfig)

	secretDir := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(secretDir, "my_token"), "secret")
	_ = os.Chmod(filepath.Join(secretDir, "my_token"), 0o400)

	var out bytes.Buffer
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain, []string{
		"/bin/sh", "-c", "touch /run/secrets/injected 2>&1",
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.SecretDir = secretDir
	plan.Stdout = &out
	plan.Stderr = &out

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	code, _ := sb.Wait()
	if code == 0 {
		t.Errorf("sandbox should fail writing to /run/secrets:\n%s", out.String())
	}
	if !strings.Contains(strings.ToLower(out.String()), "read-only") {
		t.Errorf("expected Read-only file system error, got:\n%s", out.String())
	}
}

// TestSandboxSecretsHostFileBind verifies that static host files declared in
// user config secrets: map are mounted read-only at /run/secrets/<name>.
func TestSandboxSecretsHostFileBind(t *testing.T) {
	dir := t.TempDir()
	findBwrap(t)
	writeFile(t, filepath.Join(dir, ".keg.yaml"), repoConfig)

	hostKeyFile := filepath.Join(t.TempDir(), "github-pat.txt")
	writeFile(t, hostKeyFile, "ghp_secret_token_12345")

	var out bytes.Buffer
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain, []string{
		"/bin/sh", "-c", `cat /run/secrets/github_pat && cat "$GITHUB_PAT_FILE"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.SecretPathBinds = []orchestrator.SecretBind{
		{HostPath: hostKeyFile, GuestPath: "/run/secrets/github_pat"},
	}
	plan.EnvSet["GITHUB_PAT_FILE"] = "/run/secrets/github_pat"
	plan.Stdout = &out
	plan.Stderr = &out

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}

	want := "ghp_secret_token_12345ghp_secret_token_12345"
	if strings.TrimSpace(out.String()) != want {
		t.Errorf("got %q, want %q", strings.TrimSpace(out.String()), want)
	}
}
