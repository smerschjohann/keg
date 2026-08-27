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

func TestMergeVars_CLIVarsHighestPrecedence(t *testing.T) {
	repoVars := map[string]string{"key": "repo", "only_repo": "1"}
	userGlobal := map[string]string{"key": "user", "only_user": "2"}
	repoOverride := map[string]string{"key": "match", "only_match": "3"}
	cliVars := map[string]string{"key": "cli", "only_cli": "4", "FROM_ENV": "cli_override"}

	t.Setenv("KEG_VAR_FROM_ENV", "envval")
	vars := MergeVars(repoVars, userGlobal, repoOverride, cliVars)

	if vars["key"] != "cli" {
		t.Errorf("vars[key] = %q, want %q (cli vars must have highest precedence)", vars["key"], "cli")
	}
	if vars["FROM_ENV"] != "cli_override" {
		t.Errorf("vars[FROM_ENV] = %q, want %q (cli vars must override KEG_VAR_*)", vars["FROM_ENV"], "cli_override")
	}
	if vars["only_repo"] != "1" || vars["only_user"] != "2" || vars["only_match"] != "3" || vars["only_cli"] != "4" {
		t.Errorf("unexpected merged vars: %+v", vars)
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

func TestMergeUsers_RepoOverrideSecretNeedsAdded(t *testing.T) {
	u := userFromYAML(t, `secret_sources:
  ai_token:
    cmd: [genkey, i, "60"]
repos:
  "/home/coder/dev/llmgate":
    secrets:
      - name: ai_token
      - name: db_password
        env: DB_PASSWORD_FILE
`)
	got := MatchRepo(u, "/home/coder/dev/llmgate")

	want := []string{"ai_token", "db_password"}
	if len(got.InjectNeeds) != len(want) {
		t.Fatalf("InjectNeeds = %+v, want %v", got.InjectNeeds, want)
	}
	for i, w := range want {
		if got.InjectNeeds[i].Name != w {
			t.Errorf("InjectNeeds[%d].Name = %q, want %q", i, got.InjectNeeds[i].Name, w)
		}
	}
	if got.InjectNeeds[1].Env != "DB_PASSWORD_FILE" {
		t.Errorf("InjectNeeds[1].Env = %q, want DB_PASSWORD_FILE", got.InjectNeeds[1].Env)
	}
}

func TestMergeEnv_InheritSemantics(t *testing.T) {
	tests := []struct {
		name string
		base EnvSpec
		over EnvSpec
		want EnvSpec
	}{
		{
			name: "union of inherit and map merge of set",
			base: EnvSpec{
				Set:        map[string]string{"A": "1", "B": "2"},
				Unset:      []string{"U1"},
				Inherit:    []string{"LANG", "LC_ALL"},
				InheritAll: false,
			},
			over: EnvSpec{
				Set:        map[string]string{"B": "over", "C": "3"},
				Unset:      []string{"U1", "U2"},
				Inherit:    []string{"TERM", "LANG"},
				InheritAll: true,
			},
			want: EnvSpec{
				Set:        map[string]string{"A": "1", "B": "over", "C": "3"},
				Unset:      []string{"U1", "U2"},
				Inherit:    []string{"LANG", "LC_ALL", "TERM"},
				InheritAll: true,
			},
		},
		{
			name: "inherit_all true in base preserved when false in over",
			base: EnvSpec{
				InheritAll: true,
			},
			over: EnvSpec{
				InheritAll: false,
			},
			want: EnvSpec{
				Set:        map[string]string{},
				Unset:      nil,
				Inherit:    nil,
				InheritAll: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeEnv(tt.base, tt.over)
			if got.InheritAll != tt.want.InheritAll {
				t.Errorf("InheritAll = %v, want %v", got.InheritAll, tt.want.InheritAll)
			}
			if len(got.Inherit) != len(tt.want.Inherit) {
				t.Fatalf("Inherit = %v, want %v", got.Inherit, tt.want.Inherit)
			}
			for i, v := range tt.want.Inherit {
				if got.Inherit[i] != v {
					t.Errorf("Inherit[%d] = %q, want %q", i, got.Inherit[i], v)
				}
			}
			for k, v := range tt.want.Set {
				if got.Set[k] != v {
					t.Errorf("Set[%s] = %q, want %q", k, got.Set[k], v)
				}
			}
			for i, v := range tt.want.Unset {
				if got.Unset[i] != v {
					t.Errorf("Unset[%d] = %q, want %q", i, got.Unset[i], v)
				}
			}
		})
	}
}

func TestMergeEnv_RepoBeatsGlobalSet(t *testing.T) {
	global := EnvSpec{
		Set:     map[string]string{"VAR": "global", "GLOBAL": "1"},
		Inherit: []string{"BASE_INHERIT"},
	}
	repo := EnvSpec{
		Set:     map[string]string{"VAR": "repo", "REPO": "1"},
		Inherit: []string{"REPO_INHERIT"},
	}
	got := MergeEnvChain(global, repo, EnvSpec{}, EnvSpec{})
	if got.Set["VAR"] != "repo" {
		t.Errorf("got.Set[VAR] = %q, want repo", got.Set["VAR"])
	}
	if got.Set["GLOBAL"] != "1" || got.Set["REPO"] != "1" {
		t.Errorf("got.Set = %v, want both keys", got.Set)
	}
	if len(got.Inherit) != 2 || got.Inherit[0] != "BASE_INHERIT" || got.Inherit[1] != "REPO_INHERIT" {
		t.Errorf("got.Inherit = %v, want [BASE_INHERIT REPO_INHERIT]", got.Inherit)
	}
}

func TestMergeEnv_ReposOverrideBeatsRepo(t *testing.T) {
	global := EnvSpec{Set: map[string]string{"VAR": "global"}}
	repo := EnvSpec{Set: map[string]string{"VAR": "repo"}}
	override := EnvSpec{Set: map[string]string{"VAR": "override"}}
	got := MergeEnvChain(global, repo, override, EnvSpec{})
	if got.Set["VAR"] != "override" {
		t.Errorf("got.Set[VAR] = %q, want override", got.Set["VAR"])
	}
}

func TestMergeEnv_CliBeatsAll(t *testing.T) {
	global := EnvSpec{Set: map[string]string{"VAR": "global"}}
	repo := EnvSpec{Set: map[string]string{"VAR": "repo"}}
	override := EnvSpec{Set: map[string]string{"VAR": "override"}}
	cli := EnvSpec{Set: map[string]string{"VAR": "cli"}}
	got := MergeEnvChain(global, repo, override, cli)
	if got.Set["VAR"] != "cli" {
		t.Errorf("got.Set[VAR] = %q, want cli", got.Set["VAR"])
	}
}
