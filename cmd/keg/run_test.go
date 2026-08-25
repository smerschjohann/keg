package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

const fixtureRepoYAML = `
version: "1"
env:
  set:
    LOG_FORMAT: json
  unset:
    - AWS_SESSION_TOKEN
network:
  allowed_domains:
    - proxy.golang.org
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRunPlan_MissingRepoConfigIsClearError(t *testing.T) {
	dir := t.TempDir()
	_, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "")
	if err == nil {
		t.Fatal("missing repo config must fail")
	}
	if !strings.Contains(err.Error(), ".keg.yaml") {
		t.Errorf("error must name the expected file: %v", err)
	}
}

func TestBuildRunPlan_Minimal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	wantRoot, _ := filepath.EvalSymlinks(dir)
	if plan.RepoRoot != wantRoot && plan.RepoRoot != filepath.Clean(dir) {
		t.Errorf("RepoRoot = %q, want %q", plan.RepoRoot, wantRoot)
	}
	if plan.EnvSet["LOG_FORMAT"] != "json" {
		t.Errorf("EnvSet = %v, want LOG_FORMAT=json", plan.EnvSet)
	}
	found := false
	for _, v := range plan.EnvUnset {
		if v == "AWS_SESSION_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Errorf("EnvUnset = %v, want AWS_SESSION_TOKEN", plan.EnvUnset)
	}
	if len(plan.Command) != 0 {
		t.Errorf("Command must be filled by caller, got %v", plan.Command)
	}
}

func TestBuildRunPlan_ExplicitUserConfigMustExist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	if _, err := buildRunPlan(dir, "", missing, orchestrator.OverlayPlain, ""); err == nil {
		t.Error("explicitly requested user config must exist (loud failure beats silent defaults)")
	}
}

func TestBuildRunPlan_ExplicitConfigPathWins(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(t.TempDir(), "other.yaml")
	writeFile(t, custom, "version: \"1\"\n")
	writeFile(t, filepath.Join(dir, ".keg.yaml"), "version: \"1\"\ntemplates: [go]\n")

	plan, err := buildRunPlan(dir, custom, "", orchestrator.OverlayPlain, "")
	if err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
	if len(plan.Mounts) != 0 {
		t.Errorf("explicit config path must be used verbatim")
	}
}

func TestBuildRunPlan_OverlayFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), fixtureRepoYAML)

	plan, err := buildRunPlan(dir, "", "", orchestrator.OverlayEphemeral, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Overlay.String() != "ephemeral" {
		t.Errorf("overlay = %v, want ephemeral", plan.Overlay)
	}

	diskBase := t.TempDir()
	t.Setenv("KEG_TEST_STORAGE", diskBase)
	userCfg := filepath.Join(t.TempDir(), "user.yaml")
	writeFile(t, userCfg, `
paths:
  storage_base: $KEG_TEST_STORAGE/layers
`)
	plan, err = buildRunPlan(dir, "", userCfg, orchestrator.OverlayDisk, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Overlay.String() != "disk" {
		t.Errorf("overlay = %v, want disk", plan.Overlay)
	}
	if plan.DiskLayerRW == "" || plan.DiskLayerWork == "" {
		t.Errorf("disk layer dirs not prepared: rw=%q work=%q", plan.DiskLayerRW, plan.DiskLayerWork)
	}
	if !strings.HasPrefix(plan.DiskLayerRW, diskBase) {
		t.Errorf("layer dir %q must live under storage base %q", plan.DiskLayerRW, diskBase)
	}
}

func TestBuildRunPlan_VarsFromEnvOverride(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"),
		"version: \"1\"\nvars:\n  greeting: repo\n")
	t.Setenv("KEG_VAR_greeting", "environment")

	// The merged var space is not directly observable via Plan yet
	// (templates land in WP-M4); assert no error and document intent.
	if _, err := buildRunPlan(dir, "", "", orchestrator.OverlayPlain, ""); err != nil {
		t.Fatalf("buildRunPlan: %v", err)
	}
}
