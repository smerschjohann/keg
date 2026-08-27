//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/trust"
)

func TestSandboxDefaultDeniesHostEnv(t *testing.T) {
	t.Setenv("UNAPPROVED_HOST_VAR", "super-secret-123")
	dir := t.TempDir()

	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `printf "%s" "${UNAPPROVED_HOST_VAR-EMPTY}"`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "EMPTY" {
		t.Errorf("unapproved host variable leaked into sandbox: got %q, want EMPTY", out)
	}
}

func TestSandboxRepoInheritFromKegYaml(t *testing.T) {
	t.Setenv("PASSED_HOST_VAR", "forward-me-123")
	dir := t.TempDir()

	cfg := `
version: "1"
env:
  inherit:
    - PASSED_HOST_VAR
`
	out, code := runInSandboxWithConfig(t, dir, cfg, orchestrator.OverlayPlain, `printf "%s" "$PASSED_HOST_VAR"`, func(plan *orchestrator.Plan) {
		plan.EnvInherit = []string{"PASSED_HOST_VAR"}
	}, nil)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "forward-me-123" {
		t.Errorf("repo inherited host variable missing: got %q, want forward-me-123", out)
	}
}

func TestSandboxUserConfigInherit(t *testing.T) {
	findBwrap(t)
	t.Setenv("USER_INHERITED_VAR", "user-forward-456")
	dir := t.TempDir()

	repoCfg := "version: \"1\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(repoCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	storePath := trust.DefaultTrustPath()
	store, _ := trust.LoadFile(storePath)
	_, _ = trust.Approve(store, dir, []byte(repoCfg), nil)
	_ = trust.SaveFile(storePath, store)

	userCfgPath := filepath.Join(t.TempDir(), "user-config.yaml")
	userCfg := `
env:
  inherit:
    - USER_INHERITED_VAR
`
	if err := os.WriteFile(userCfgPath, []byte(userCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, _, err := orchestrator.BuildPlan(dir, "", userCfgPath, orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	var out bytes.Buffer
	plan.Stdout = &out
	plan.Stderr = &out
	plan.Command = []string{"/bin/sh", "-c", `printf "%s" "$USER_INHERITED_VAR"`}

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer sb.Close()

	code, err := sb.Wait()
	if err != nil || code != 0 {
		t.Fatalf("sandbox run failed: code=%d err=%v\n%s", code, err, out.String())
	}
	if out.String() != "user-forward-456" {
		t.Errorf("user config inherited variable missing: got %q, want user-forward-456", out.String())
	}
}

func TestSandboxInheritAllForwardsHostEnv(t *testing.T) {
	t.Setenv("GENERIC_HOST_VAR", "visible-789")
	t.Setenv("AWS_SESSION_TOKEN", "leak-token")
	t.Setenv("HTTPS_PROXY", "http://leak:3128")
	dir := t.TempDir()

	cfg := `
version: "1"
env:
  inherit_all: true
`
	out, code := runInSandboxWithConfig(t, dir, cfg, orchestrator.OverlayPlain,
		`printf "%s|%s|%s" "${GENERIC_HOST_VAR-EMPTY}" "${AWS_SESSION_TOKEN-EMPTY}" "${HTTPS_PROXY-EMPTY}"`,
		func(plan *orchestrator.Plan) {
			plan.EnvInheritAll = true
		}, nil)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "visible-789|EMPTY|EMPTY" {
		t.Errorf("inherit_all output mismatch: got %q, want 'visible-789|EMPTY|EMPTY'", out)
	}
}

func TestSandboxCliEnvFlag(t *testing.T) {
	t.Setenv("CLI_PASSED_VAR", "cli-val")
	dir := t.TempDir()

	out, code := runInSandboxWithConfig(t, dir, "version: \"1\"\n", orchestrator.OverlayPlain,
		`printf "%s|%s" "$CLI_PASSED_VAR" "$CLI_EXPLICIT_VAR"`,
		func(plan *orchestrator.Plan) {
			plan.EnvInherit = append(plan.EnvInherit, "CLI_PASSED_VAR")
			plan.EnvSet["CLI_EXPLICIT_VAR"] = "explicit"
		}, nil)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "cli-val|explicit" {
		t.Errorf("CLI env output mismatch: got %q, want 'cli-val|explicit'", out)
	}
}

func TestSandboxInheritAllWithExplicitDeniedFlag(t *testing.T) {
	t.Setenv("GENERIC_HOST_VAR", "visible-val")
	t.Setenv("AWS_SESSION_TOKEN", "my-session-token")
	t.Setenv("HTTPS_PROXY", "http://corp:3128")
	dir := t.TempDir()

	cfg := "version: \"1\"\n"
	out, code := runInSandboxWithConfig(t, dir, cfg, orchestrator.OverlayPlain,
		`printf "%s|%s|%s" "${GENERIC_HOST_VAR-EMPTY}" "${AWS_SESSION_TOKEN-EMPTY}" "${HTTPS_PROXY-EMPTY}"`,
		func(plan *orchestrator.Plan) {
			plan.EnvInheritAll = true
			if val, ok := os.LookupEnv("AWS_SESSION_TOKEN"); ok {
				plan.EnvSet["AWS_SESSION_TOKEN"] = val
			}
		}, nil)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "visible-val|my-session-token|EMPTY" {
		t.Errorf("expected combined inherit-all and -e AWS_SESSION_TOKEN to yield 'visible-val|my-session-token|EMPTY', got %q", out)
	}
}

func TestSandboxTrustGate(t *testing.T) {
	findBwrap(t)
	dir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", trustDir)

	cfg := "version: \"1\"\nenv:\n  set:\n    TRUSTED_VAR: \"approved\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Untrusted in non-TTY fails
	_, _, err := orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil || !strings.Contains(err.Error(), "keg trust") {
		t.Fatalf("untrusted repo config must fail mentioning 'keg trust', got: %v", err)
	}

	// 2. Approve via trust store
	trustStorePath := filepath.Join(trustDir, "keg", "trust.yaml")
	store, _ := trust.LoadFile(trustStorePath)
	_, err = trust.Approve(store, dir, []byte(cfg), nil)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := trust.SaveFile(trustStorePath, store); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	// 3. Now BuildPlan & Launch succeed
	plan, _, err := orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("BuildPlan after approve: %v", err)
	}

	var out bytes.Buffer
	plan.Stdout = &out
	plan.Stderr = &out
	plan.Command = []string{"/bin/sh", "-c", `printf "%s" "$TRUSTED_VAR"`}

	sb, err := orchestrator.Launch(context.Background(), plan)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer sb.Close()

	code, err := sb.Wait()
	if err != nil || code != 0 {
		t.Fatalf("run failed: code=%d err=%v\n%s", code, err, out.String())
	}
	if out.String() != "approved" {
		t.Errorf("output = %q, want 'approved'", out.String())
	}
}

func TestSandboxTrustGate_Changed(t *testing.T) {
	findBwrap(t)
	dir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", trustDir)

	cfg1 := "version: \"1\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(cfg1), 0o644); err != nil {
		t.Fatal(err)
	}
	trustStorePath := filepath.Join(trustDir, "keg", "trust.yaml")
	store, _ := trust.LoadFile(trustStorePath)
	_, _ = trust.Approve(store, dir, []byte(cfg1), nil)
	_ = trust.SaveFile(trustStorePath, store)

	// First run succeeds
	_, _, err := orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("initial BuildPlan failed: %v", err)
	}

	// Modify config
	cfg2 := "version: \"1\"\nenv:\n  set:\n    NEW_KEY: 1\n"
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(cfg2), 0o644); err != nil {
		t.Fatal(err)
	}

	// Now BuildPlan must fail because content changed
	_, _, err = orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil || !strings.Contains(err.Error(), "keg trust") {
		t.Fatalf("changed repo config must fail mentioning 'keg trust', got: %v", err)
	}
}

func TestSandboxTrustGate_TrustAnchors(t *testing.T) {
	findBwrap(t)
	dir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", trustDir)

	cfg := "version: \"1\"\ntrust_anchors:\n  - Makefile\n"
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	makeContent := "all:\n\techo build\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makeContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Initial BuildPlan fails before approve
	_, _, err := orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil {
		t.Fatalf("expected unapproved trust anchors to fail")
	}

	// 2. Approve config and anchor
	trustStorePath := filepath.Join(trustDir, "keg", "trust.yaml")
	store, _ := trust.LoadFile(trustStorePath)
	_, _ = trust.Approve(store, dir, []byte(cfg), map[string][]byte{"Makefile": []byte(makeContent)})
	_ = trust.SaveFile(trustStorePath, store)

	// 3. BuildPlan succeeds
	_, _, err = orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err != nil {
		t.Fatalf("BuildPlan after approving anchors failed: %v", err)
	}

	// 4. Modify Makefile -> BuildPlan fails
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n\tmalicious\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err = orchestrator.BuildPlan(dir, "", "", orchestrator.OverlayPlain, "", orchestrator.OverlayPlain, "", "")
	if err == nil || !strings.Contains(err.Error(), "keg trust") {
		t.Fatalf("modified anchor must fail mentioning 'keg trust', got: %v", err)
	}
}
