package runner

import (
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
)

// gitRule mirrors the proven host_runner.py git pattern (CONCEPT.md §4.5).
func gitRule() config.RawRule {
	return config.RawRule{
		Cmd: "git",
		Subcommands: []string{
			"add", "branch", "checkout", "commit", "diff", "fetch",
			"log", "merge", "rebase", "reset", "show", "stash",
			"ls-files", "status", "switch",
		},
		OptsWithValue:     []string{"-c", "-C", "--git-dir", "--work-tree", "--namespace"},
		Flags:             []string{"--no-pager", "--paginate", "--bare", "--literal-pathspecs"},
		AllowOptValueForm: true,
		ForbiddenArgsMatching: []string{
			"https://*", "http://*", "git@*", "ssh://*",
		},
	}
}

func TestEngine_Match(t *testing.T) {
	engine, err := NewEngine(
		config.DelegatedTasks{
			Exact:    []string{"container-build"},
			Prefixes: []string{"test-playwright"},
			Raw:      []config.RawRule{gitRule()},
		},
		config.RunnerCfg{},
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name  string
		argv  []string
		allow bool
		kind  Kind
	}{
		{
			name:  "exact task without arguments is allowed",
			argv:  []string{"container-build"},
			allow: true,
			kind:  KindJust,
		},
		{
			name:  "exact task with extra argument is denied",
			argv:  []string{"container-build", "extra"},
			allow: false,
		},
		{
			name:  "unknown task is denied",
			argv:  []string{"deploy-prod"},
			allow: false,
		},
		{
			name:  "prefix task passes trailing arguments",
			argv:  []string{"test-playwright", "login.spec.ts", "-g", "auth"},
			allow: true,
			kind:  KindJust,
		},
		{
			name: "prefix class does not fire on lookalike task",
			argv: []string{"test-playwrightx", "login.spec.ts"},
		},
		{
			name:  "prefix task without arguments is allowed",
			argv:  []string{"test-playwright"},
			allow: true,
			kind:  KindJust,
		},

		// Raw class: git semantics from the proven bestand.
		{
			name:  "git status plain is allowed",
			argv:  []string{"git", "status"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name:  "git commit with message is allowed",
			argv:  []string{"git", "commit", "-m", "meine nachricht"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name:  "global option with value then subcommand is allowed",
			argv:  []string{"git", "-c", "user.email=x@y", "commit", "--amend"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name:  "global flag then subcommand is allowed",
			argv:  []string{"git", "--no-pager", "diff"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name:  "selfstanding --opt=value form is allowed",
			argv:  []string{"git", "--namespace=org/repo", "log"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name:  "selfstanding --opt=value form for opts_with_value is accepted",
			argv:  []string{"git", "--git-dir=/somewhere", "status"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name: "first free argument outside subcommands is denied",
			argv: []string{"git", "push", "origin", "main"},
		},
		{
			name: "push is never whitelisted even with options",
			argv: []string{"git", "--no-pager", "push", "--force"},
		},
		{
			name: "URL in fetch arguments hits forbidden glob",
			argv: []string{"git", "fetch", "https://evil.example/pwn.git"},
		},
		{
			name: "scp-style remote hits forbidden glob",
			argv: []string{"git", "fetch", "git@evil.example:pwn.git"},
		},
		{
			name: "ssh scheme hits forbidden glob",
			argv: []string{"git", "pull", "ssh://git@evil.example/pwn.git"},
		},
		{
			name: "forbidden check covers everything after the subcommand",
			argv: []string{"git", "commit", "-m", "ok", "http://tracker.example/x"},
		},
		{
			name:  "known option value containing URL is consumed before policy",
			argv:  []string{"git", "-C", "/repo", "status"},
			allow: true,
			kind:  KindRaw,
		},
		{
			name: "dangling option value is denied",
			argv: []string{"git", "-C"},
		},
		{
			name: "unknown global option is denied",
			argv: []string{"git", "--exec-path=/tmp/evil", "status"},
		},
		{
			name: "subcommand before options is required",
			argv: []string{"git"},
		},
		{
			name: "empty argv is denied",
			argv: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.Match(tt.argv)
			if got.Allow != tt.allow {
				t.Fatalf("Match(%q) allow=%v, want %v (reason: %s)",
					tt.argv, got.Allow, tt.allow, got.Reason)
			}
			if tt.allow && got.Kind != tt.kind {
				t.Errorf("Match(%q) kind=%v, want %v", tt.argv, got.Kind, tt.kind)
			}
			if !tt.allow && strings.TrimSpace(got.Reason) == "" {
				t.Errorf("Match(%q): denial must carry a reason", tt.argv)
			}
			if tt.allow && got.Reason != "" {
				t.Errorf("Match(%q): unexpected reason %q on allow", tt.argv, got.Reason)
			}
		})
	}
}

func TestMatchRaw_LongestPrefixOptionsAreOrderIndependent(t *testing.T) {
	rule := config.RawRule{
		Cmd:               "podman",
		Subcommands:       []string{"build", "images"},
		OptsWithValue:     []string{"--format", "--platform"},
		Flags:             []string{"--no-cache"},
		AllowOptValueForm: true,
	}
	tests := []struct {
		name  string
		argv  []string
		allow bool
	}{
		{"value form", []string{"podman", "--platform=linux/amd64", "build"}, true},
		{"separate value", []string{"podman", "--platform", "linux/amd64", "images"}, true},
		{"flag then subcommand", []string{"podman", "--no-cache", "build"}, true},
		{"unknown subcommand", []string{"podman", "run", "-it", "alpine"}, false},
		{"option after subcommand stays untouched", []string{"podman", "build", "--platform", "linux/arm64"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchRaw(tt.argv, rule); got.Allow != tt.allow {
				t.Fatalf("MatchRaw(%q) allow=%v want %v (reason: %s)",
					tt.argv, got.Allow, tt.allow, got.Reason)
			}
		})
	}
}

func TestMatchRaw_OptValueFormRequiresConsent(t *testing.T) {
	rule := config.RawRule{
		Cmd:           "git",
		Subcommands:   []string{"status"},
		OptsWithValue: []string{"--git-dir"},
	}
	if got := MatchRaw([]string{"git", "--git-dir=/tmp/evil", "status"}, rule); got.Allow {
		t.Error("--opt=value accepted without allow_opt_value_form — must be denied")
	}
}

func TestForbiddenMatching(t *testing.T) {
	tests := []struct {
		pattern string
		arg     string
		want    bool
	}{
		// Glob semantics: '*' spans any characters including '/'.
		{"https://*", "https://evil.example/pwn.git", true},
		{"https://*", "http://evil.example", false},
		{"git@*", "git@github.com:org/repo.git", true},
		// '?': exactly one character, any value (glob semantics are
		// case-insensitive about position, literals stay case-sensitive).
		{"file?a", "filexa", true},
		{"file?a", "fileaa", true},
		{"File?a", "filexa", false}, // literal case mismatch
		// Consistent with '*': '?' also spans '/' (URL-friendly glob).
		{"file?a", "file/a", true},
		// Literal patterns match exactly.
		{"--amend", "--amend", true},
		{"--amend", "--amendx", false},
		// /regex/ form.
		{"/^refs\\/heads\\/(main|release-.*)$/", "refs/heads/release-2024", true},
		{"/^refs\\/heads\\/(main|release-.*)$/", "refs/heads/dev", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"~"+tt.arg, func(t *testing.T) {
			if got := forbiddenMatch(tt.pattern, tt.arg); got != tt.want {
				t.Fatalf("forbiddenMatch(%q, %q) = %v, want %v", tt.pattern, tt.arg, got, tt.want)
			}
		})
	}
}

func TestNewEngine_Errors(t *testing.T) {
	tests := []struct {
		name    string
		tasks   config.DelegatedTasks
		wantMsg string
	}{
		{
			name: "empty subcommands set is a configuration error",
			tasks: config.DelegatedTasks{
				Raw: []config.RawRule{{Cmd: "git"}},
			},
			wantMsg: "subcommands must not be empty",
		},
		{
			name: "invalid regex pattern is a configuration error",
			tasks: config.DelegatedTasks{
				Raw: []config.RawRule{{
					Cmd:                   "git",
					Subcommands:           []string{"fetch"},
					ForbiddenArgsMatching: []string{"/([unclosed/"},
				}},
			},
			wantMsg: "invalid regex",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine(tt.tasks, config.RunnerCfg{})
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("NewEngine() error = %v, want containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestNewEngine_MergesUserExtrasAsUnion(t *testing.T) {
	engine, err := NewEngine(
		config.DelegatedTasks{
			Exact:    []string{"container-build"},
			Prefixes: []string{"test-playwright"},
		},
		config.RunnerCfg{
			ExtraExact:    []string{"k8s-deploy"},
			ExtraPrefixes: []string{"install-playwright"},
			ExtraRaw: []config.RawRule{{
				Cmd:         "podman",
				Subcommands: []string{"images"},
			}},
		},
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, argv := range [][]string{
		{"container-build"},
		{"k8s-deploy"},
		{"test-playwright", "a.spec.ts"},
		{"install-playwright", "chromium"},
		{"podman", "images"},
	} {
		if got := engine.Match(argv); !got.Allow {
			t.Errorf("Match(%q) denied, want allowed (reason: %s)", argv, got.Reason)
		}
	}
	// User extras add permissions; they never remove repo ones, but they
	// also never bypass the raw matcher's deny-by-default.
	if got := engine.Match([]string{"podman", "run"}); got.Allow {
		t.Error("Match(podman run) allowed, want denied")
	}
}

func TestInvariant_DelegationDenyByDefault(t *testing.T) {
	// THREAT_MODEL §5.4/§8: an empty whitelist delegates NOTHING.
	engine, err := NewEngine(config.DelegatedTasks{}, config.RunnerCfg{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, argv := range [][]string{
		{"git", "status"},
		{"just", "build"},
		{"anything"},
	} {
		if got := engine.Match(argv); got.Allow {
			t.Errorf("Match(%v) allowed with EMPTY whitelist — deny-by-default violated", argv)
		}
	}
}
