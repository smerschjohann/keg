package config

import (
	"strings"
	"testing"
	"time"
)

const minimalRepo = `
version: "1"
templates:
  - go
network:
  sni_domains:
    - proxy.golang.org
`

func TestParseRepo_MinimalValid(t *testing.T) {
	repo, err := ParseRepo([]byte(minimalRepo))
	if err != nil {
		t.Fatalf("minimal config must parse: %v", err)
	}
	if repo.Version != "1" {
		t.Errorf("version = %q, want %q", repo.Version, "1")
	}
	if len(repo.Templates) != 1 || repo.Templates[0] != "go" {
		t.Errorf("templates = %v, want [go]", repo.Templates)
	}
	domains := repo.Network.SNIDomains
	if len(domains) != 1 || domains[0] != "proxy.golang.org" {
		t.Errorf("allowed_domains = %v", domains)
	}
}

func TestParseRepo_RejectsUnknownField(t *testing.T) {
	tests := []struct {
		name     string
		yamlText string
		wantPath string
	}{
		{
			name:     "top level typo",
			yamlText: "version: \"1\"\nmountss: []\n",
			wantPath: "mountss",
		},
		{
			name:     "nested network typo",
			yamlText: "version: \"1\"\nnetwork:\n  allowd_domains: [a]\n",
			wantPath: "allowd_domains",
		},
		{
			name:     "mount unknown key",
			yamlText: "version: \"1\"\nmounts:\n  - src: /a\n    dest: /b\n    modus: rw\n",
			wantPath: "modus",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRepo([]byte(tt.yamlText))
			if err == nil {
				t.Fatalf("unknown field must fail")
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("error %q must mention field path %q", err, tt.wantPath)
			}
		})
	}
}

func TestParseRepo_ValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		yamlText string
		wantErr  string
	}{
		{
			name:     "missing version",
			yamlText: "network:\n  sni_domains: [a]\n",
			wantErr:  "version",
		},
		{
			name:     "unsupported version",
			yamlText: "version: \"99\"\n",
			wantErr:  "version",
		},
		{
			name:     "unknown template",
			yamlText: "version: \"1\"\ntemplates: [cobol]\n",
			wantErr:  "cobol",
		},
		{
			name:     "invalid mount mode",
			yamlText: "version: \"1\"\nmounts:\n  - src: /a\n    dest: /b\n    mode: exec\n",
			wantErr:  "mode",
		},
		{
			name:     "raw rule without subcommands",
			yamlText: "version: \"1\"\ndelegated_tasks:\n  raw:\n    - cmd: git\n",
			wantErr:  "subcommands",
		},
		{
			name:     "invalid port spec",
			yamlText: "version: \"1\"\nports:\n  - \"foo:bar\"\n",
			wantErr:  "port",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRepo([]byte(tt.yamlText))
			if err == nil {
				t.Fatalf("must fail")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("error %q must mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseRepo_PortSpecs(t *testing.T) {
	tests := []struct {
		name       string
		spec       string
		wantGuest  int
		wantHost   int
		wantName   string
		wantDynami bool
	}{
		{name: "plain port", spec: "\"3000\"", wantGuest: 3000, wantHost: 3000},
		{name: "mapping", spec: "\"5432:15432\"", wantGuest: 5432, wantHost: 15432},
		{
			name:       "named dynamic",
			spec:       "{name: dev-server, port: 8080, dynamic: true}",
			wantGuest:  8080,
			wantHost:   8080,
			wantName:   "dev-server",
			wantDynami: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := ParseRepo([]byte("version: \"1\"\nports:\n  - " + tt.spec + "\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(repo.Ports) != 1 {
				t.Fatalf("got %d ports, want 1", len(repo.Ports))
			}
			p := repo.Ports[0]
			if p.Guest != tt.wantGuest || p.Host != tt.wantHost {
				t.Errorf("guest/host = %d/%d, want %d/%d", p.Guest, p.Host, tt.wantGuest, tt.wantHost)
			}
			if p.Name != tt.wantName {
				t.Errorf("name = %q, want %q", p.Name, tt.wantName)
			}
			if p.Dynamic != tt.wantDynami {
				t.Errorf("dynamic = %v, want %v", p.Dynamic, tt.wantDynami)
			}
		})
	}
}

func TestParseUser_MinimalAndDefaults(t *testing.T) {
	user, err := ParseUser([]byte(""))
	if err != nil {
		t.Fatalf("empty user config must parse: %v", err)
	}
	if user.Paths.StorageBase != "" {
		t.Errorf("empty config must not invent values, got storage_base=%q", user.Paths.StorageBase)
	}
}

func TestParseUser_SecretSourceWithDuration(t *testing.T) {
	user, err := ParseUser([]byte(`
secret_sources:
  ai_token:
    cmd: [op, read, op://x/y]
    interval: 5m
    timeout: 10s
    on_refresh_error: fail
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	src, ok := user.SecretSources["ai_token"]
	if !ok {
		t.Fatal("secret source ai_token missing")
	}
	if src.Interval.Duration != 5*time.Minute {
		t.Errorf("interval = %v, want 5m", src.Interval.Duration)
	}
	if src.Timeout.Duration != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", src.Timeout.Duration)
	}
	if src.OnRefreshError != "fail" {
		t.Errorf("on_refresh_error = %q, want fail", src.OnRefreshError)
	}
}

func TestParseUser_RejectsUnknownField(t *testing.T) {
	_, err := ParseUser([]byte("paths:\n  storage_basee: /x\n"))
	if err == nil {
		t.Fatal("unknown user field must fail")
	}
	if !strings.Contains(err.Error(), "storage_basee") {
		t.Errorf("error must mention field path: %v", err)
	}
}

func TestExpandPath(t *testing.T) {
	t.Setenv("KEG_TEST_BASE", "/opt/base")
	tests := []struct {
		name    string
		in      string
		home    string
		want    string
		wantErr bool
	}{
		{name: "literal", in: "/var/lib/x", want: "/var/lib/x"},
		{name: "tilde", in: "~/work/*", home: "/home/u", want: "/home/u/work/*"},
		{name: "env var", in: "$KEG_TEST_BASE/layers", want: "/opt/base/layers"},
		{name: "braced env var", in: "${KEG_TEST_BASE}/layers", want: "/opt/base/layers"},
		{name: "unset var", in: "$KEG_TEST_MISSING/x", wantErr: true},
		{name: "tilde alone", in: "~", home: "/home/u", want: "/home/u"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", tt.home)
			got, err := ExpandPath(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ExpandPath(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExpandPath(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ExpandPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
