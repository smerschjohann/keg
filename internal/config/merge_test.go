package config

import (
	"testing"
)

// userFromYAML is a test helper that must panic on invalid input — tests
// only feed valid YAML here.
func userFromYAML(t *testing.T, s string) *User {
	t.Helper()
	u, err := ParseUser([]byte(s))
	if err != nil {
		t.Fatalf("parse user config: %v", err)
	}
	return u
}

func TestMergeUsers_ScalarsReplaced(t *testing.T) {
	base := userFromYAML(t, `
paths:
  storage_base: /a
  tmp_base: /tmp
runner:
  just_bin: just
security:
  allow_weak_bwrap: false
`)
	override := userFromYAML(t, `
paths:
  storage_base: /b
`)
	got := MergeUsers(base, override)
	if got.Paths.StorageBase != "/b" {
		t.Errorf("storage_base = %q, want /b (later scalar wins)", got.Paths.StorageBase)
	}
	if got.Paths.TmpBase != "/tmp" {
		t.Errorf("tmp_base = %q, want /tmp (unset scalars keep base value)", got.Paths.TmpBase)
	}
	if got.Runner.JustBin != "just" {
		t.Errorf("just_bin = %q, want just", got.Runner.JustBin)
	}
}

func TestMergeUsers_ListsUnion(t *testing.T) {
	base := userFromYAML(t, `
runner:
  extra_exact: [a, b]
  extra_prefixes: [test-x]
`)
	override := userFromYAML(t, `
runner:
  extra_exact: [b, c]
`)
	got := MergeUsers(base, override)
	wantExact := []string{"a", "b", "c"}
	if len(got.Runner.ExtraExact) != len(wantExact) {
		t.Fatalf("extra_exact = %v, want %v", got.Runner.ExtraExact, wantExact)
	}
	for i, w := range wantExact {
		if got.Runner.ExtraExact[i] != w {
			t.Errorf("extra_exact[%d] = %q, want %q", i, got.Runner.ExtraExact[i], w)
		}
	}
	if len(got.Runner.ExtraPrefixes) != 1 || got.Runner.ExtraPrefixes[0] != "test-x" {
		t.Errorf("extra_prefixes = %v, want unchanged", got.Runner.ExtraPrefixes)
	}
}

func TestMergeUsers_MapsKeywise(t *testing.T) {
	base := userFromYAML(t, `
vars:
  mock_data: /data/a
  other: keep-me
`)
	override := userFromYAML(t, `
vars:
  mock_data: /data/b
`)
	got := MergeUsers(base, override)
	if got.Vars["mock_data"] != "/data/b" {
		t.Errorf("vars[mock_data] = %q, want override", got.Vars["mock_data"])
	}
	if got.Vars["other"] != "keep-me" {
		t.Errorf("vars[other] = %q, want preserved", got.Vars["other"])
	}
}

func TestMergeUsers_OverrideOnlySetsWhatItDeclares(t *testing.T) {
	base := userFromYAML(t, `
security:
  allow_weak_bwrap: true
template_env:
  allow_env: true
`)
	override := userFromYAML(t, `vars: {}`)
	got := MergeUsers(base, override)
	if !boolDeref(got.Security.AllowWeakBwrap) {
		t.Error("allow_weak_bwrap must survive a vars-only override")
	}
	if !boolDeref(got.TemplateEnv.AllowEnv) {
		t.Error("allow_env must survive a vars-only override")
	}
}

func boolDeref(b *bool) bool { return b != nil && *b }

func TestMatchRepo_ExactRealpathBeatsGlob(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	user := userFromYAML(t, `
paths:
  storage_base: /global
repos:
  "/home/u/work/proj":
    paths:
      storage_base: /exact
  "~/work/*":
    paths:
      storage_base: /glob
`)
	got := MatchRepo(user, "/home/u/work/proj")
	if got.Paths.StorageBase != "/exact" {
		t.Errorf("storage_base = %q, want /exact (exact match beats glob)", got.Paths.StorageBase)
	}
}

func TestMatchRepo_MostSpecificGlobWins(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	user := userFromYAML(t, `
paths:
  storage_base: /global
repos:
  "~/work/*":
    paths:
      storage_base: /shallow
  "~/work/team/*":
    paths:
      storage_base: /deep
`)
	got := MatchRepo(user, "/home/u/work/team/alpha")
	if got.Paths.StorageBase != "/deep" {
		t.Errorf("storage_base = %q, want /deep (deeper literal prefix wins)", got.Paths.StorageBase)
	}
}

func TestMatchRepo_NoMatchKeepsGlobal(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	user := userFromYAML(t, `
paths:
  storage_base: /global
repos:
  "~/other/*":
    paths:
      storage_base: /elsewhere
`)
	got := MatchRepo(user, "/home/u/work/proj")
	if got.Paths.StorageBase != "/global" {
		t.Errorf("storage_base = %q, want /global", got.Paths.StorageBase)
	}
}

func TestMatchRepo_TildeExpansionInPatterns(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	user := userFromYAML(t, `
repos:
  "~/w$KEG_TEST_SUFFIX":
    vars:
      marker: matched
`)
	t.Setenv("KEG_TEST_SUFFIX", "ork")
	got := MatchRepo(user, "/home/u/work")
	if got.Vars["marker"] != "matched" {
		t.Errorf("pattern with ~/$VAR did not match: vars = %v", got.Vars)
	}
}

func TestMergeVars_PrecedenceOrder(t *testing.T) {
	repoVars := map[string]string{"from": "repo", "shared": "repo"}
	userGlobal := map[string]string{"user": "yes", "shared": "global"}
	repoOverride := map[string]string{"match": "yes", "shared": "match"}

	t.Setenv("KEG_VAR_FROM_ENV", "envval")
	vars := MergeVars(repoVars, userGlobal, repoOverride)
	tests := []struct{ key, want string }{
		{"from", "repo"},
		{"user", "yes"},
		{"match", "yes"},
		{"shared", "match"}, // repos[match] wins over global and repo
	}
	for _, tt := range tests {
		if vars[tt.key] != tt.want {
			t.Errorf("vars[%s] = %q, want %q", tt.key, vars[tt.key], tt.want)
		}
	}
	if vars["FROM_ENV"] != "envval" {
		t.Errorf("vars[FROM_ENV] = %q, want env injection KEG_VAR_FROM_ENV", vars["FROM_ENV"])
	}
}

func TestMergeUsers_MountsAndNetwork(t *testing.T) {
	base := userFromYAML(t, `
mounts:
  - src: ~/.gemini
    dest: /home/sandbox/.gemini
    mode: rw
network:
  mode: proxy
  dns:
    enabled: true
    hosts:
      global.host: 1.1.1.1
  sni_domains:
    - api.anthropic.com
  tcp_endpoints:
    - host: db.internal
      ports: [5432]
env:
  set:
    GLOBAL_VAR: "1"
`)
	override := userFromYAML(t, `
mounts:
  - src: ~/.local/bin
    dest: /home/sandbox/.local/bin
    mode: ro
network:
  mode: transparent
  dns:
    hosts:
      local.host: 2.2.2.2
  sni_domains:
    - daily-cloudcode-pa.googleapis.com
  tcp_endpoints:
    - host: daily-cloudcode-pa.googleapis.com
      ports: [443]
env:
  set:
    LOCAL_VAR: "2"
`)
	got := MergeUsers(base, override)
	if len(got.Mounts) != 2 {
		t.Fatalf("mounts count = %d, want 2", len(got.Mounts))
	}
	if got.Network.Mode != "transparent" {
		t.Errorf("network.mode = %q, want transparent", got.Network.Mode)
	}
	if len(got.Network.SNIDomains) != 2 {
		t.Errorf("sni_domains = %v, want 2 domains", got.Network.SNIDomains)
	}
	if len(got.Network.TCPEndpoints) != 2 {
		t.Errorf("tcp_endpoints = %v, want 2 endpoints", got.Network.TCPEndpoints)
	}
	if got.Network.DNS.Hosts["local.host"] != "2.2.2.2" || got.Network.DNS.Hosts["global.host"] != "1.1.1.1" {
		t.Errorf("dns hosts = %v", got.Network.DNS.Hosts)
	}
	if got.Env.Set["LOCAL_VAR"] != "2" || got.Env.Set["GLOBAL_VAR"] != "1" {
		t.Errorf("env.set = %v", got.Env.Set)
	}
}
