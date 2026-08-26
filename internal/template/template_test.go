package template

import (
	"strings"
	"testing"
)

func TestApply_Vars(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		text    string
		vars    map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "plain text stays literal",
			text: "/mnt/cache/no-template",
			vars: map[string]string{"home": "/x"},
			want: "/mnt/cache/no-template",
		},
		{
			name: "var reference resolves",
			text: "{{ .Vars.cache }}/go",
			vars: map[string]string{"cache": "/mnt/gocache"},
			want: "/mnt/gocache/go",
		},
		{
			name:    "missing var without default errors",
			text:    "{{ .Vars.missing }}/x",
			vars:    map[string]string{},
			wantErr: true,
		},
		{
			name: "default fills missing var",
			text: `{{ default "/tmp/fallback" .Vars.missing }}/cache`,
			vars: map[string]string{},
			want: "/tmp/fallback/cache",
		},
		{
			name: "default keeps existing var",
			text: `{{ default "/tmp/fallback" .Vars.present }}/cache`,
			vars: map[string]string{"present": "/real"},
			want: "/real/cache",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Apply(tt.text, Context{Vars: tt.vars})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Apply(%q) = %q, want error", tt.text, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply(%q): %v", tt.text, err)
			}
			if got != tt.want {
				t.Errorf("Apply(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// TestApply_EnvGatedByAllowEnv pins THREAT_MODEL §8-adjacent policy: host
// environment is only reachable when explicitly enabled; otherwise the
// access is a configuration error, never silently empty.
func TestApply_EnvGatedByAllowEnv(t *testing.T) {
	t.Parallel()
	ctx := Context{Vars: map[string]string{}, Env: map[string]string{"HOME": "/host/home"}}

	got, err := Apply("{{ .Env.HOME }}", ctx)
	if err != nil || got != "/host/home" {
		t.Fatalf("allowed env: %q %v", got, err)
	}

	denied := Context{Vars: ctx.Vars} // Env nil = not allowed
	_, err = Apply("{{ .Env.HOME }}", denied)
	if err == nil {
		t.Fatal(".Env access without allow_env must be a configuration error")
	}
	if !strings.Contains(err.Error(), "allow_env") {
		t.Errorf("error must name the enabling flag: %v", err)
	}

	// Non-env templates still work when env is disabled.
	got, err = Apply("{{ .Vars.x }}", denied.WithVar("x", "ok"))
	if err != nil || got != "ok" {
		t.Fatalf("vars-only template broken under denied env: %q %v", got, err)
	}
}

func TestApply_UnknownFunctionErrors(t *testing.T) {
	t.Parallel()
	_, err := Apply(`{{ printf "%s" .Vars.x }}`, Context{Vars: map[string]string{"x": "y"}})
	if err == nil {
		t.Fatal("unknown template functions must be rejected (restricted language)")
	}
}

// TestApply_LineReference pins that errors carry a line reference for
// multi-line config files.
func TestApply_LineReference(t *testing.T) {
	t.Parallel()
	_, err := Apply("line1 ok\nline2 {{ .Vars.nope }}", Context{Vars: map[string]string{}})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error lacks line reference: %v", err)
	}
}
