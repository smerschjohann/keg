package config

import (
	"os"
	"path/filepath"
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

func TestParseRepo_AllowAndBlockNetworks(t *testing.T) {
	raw := `
version: "1"
network:
  sni_domains:
    - "*"
  allow_networks:
    - 10.1.2.0/24
    - 192.168.1.1
  block_networks:
    - 10.0.0.0/8
    - 169.254.169.254/32
`
	repo, err := ParseRepo([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRepo with allow/block networks failed: %v", err)
	}
	if len(repo.Network.AllowNetworks) != 2 || repo.Network.AllowNetworks[0] != "10.1.2.0/24" {
		t.Errorf("repo.Network.AllowNetworks = %v", repo.Network.AllowNetworks)
	}
	if len(repo.Network.BlockNetworks) != 2 || repo.Network.BlockNetworks[1] != "169.254.169.254/32" {
		t.Errorf("repo.Network.BlockNetworks = %v", repo.Network.BlockNetworks)
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

func TestParseUser_SecretSourceAlways(t *testing.T) {
	user, err := ParseUser([]byte(`
secret_sources:
  ai_token:
    cmd: [genkey, my-instance, "60"]
    always: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	src, ok := user.SecretSources["ai_token"]
	if !ok {
		t.Fatal("secret source ai_token missing")
	}
	if !src.Always {
		t.Errorf("source.Always = false, want true (always-inject flag)")
	}
}

func TestParseUser_SecretSourceAsync(t *testing.T) {
	user, err := ParseUser([]byte(`
secret_sources:
  ai_token:
    cmd: [genkey, my-instance, "60"]
    async: true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	src, ok := user.SecretSources["ai_token"]
	if !ok {
		t.Fatal("secret source ai_token missing")
	}
	if !src.Async {
		t.Errorf("source.Async = false, want true (async-fetch flag)")
	}
}

func TestParseUser_RepoOverrideSecretsNeed(t *testing.T) {
	user, err := ParseUser([]byte(`
repos:
  "/home/coder/dev/llmgate":
    secrets:
      - name: ai_secret_key
      - name: db_password
        env: DB_PASSWORD_FILE
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	override, ok := user.Repos["/home/coder/dev/llmgate"]
	if !ok {
		t.Fatal("repo override missing")
	}
	if len(override.Secrets) != 2 {
		t.Fatalf("override.Secrets = %+v, want 2 refs", override.Secrets)
	}
	if override.Secrets[0].Name != "ai_secret_key" {
		t.Errorf("Secrets[0].Name = %q, want ai_secret_key", override.Secrets[0].Name)
	}
	if override.Secrets[1].Env != "DB_PASSWORD_FILE" {
		t.Errorf("Secrets[1].Env = %q, want DB_PASSWORD_FILE", override.Secrets[1].Env)
	}
}

func TestValidateUser_RepoOverrideEmptySecretName(t *testing.T) {
	_, err := ParseUser([]byte(`
repos:
  "/repo":
    secrets:
      - name: ""
`))
	if err == nil {
		t.Fatal("repo override secret with empty name must be rejected")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Errorf("error %q must mention secrets", err)
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

func TestParseRepo_NetworkModeValues(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "empty mode defaults", mode: "", wantErr: false},
		{name: "proxy mode", mode: "proxy", wantErr: false},
		{name: "transparent mode", mode: "transparent", wantErr: false},
		{name: "both modes in parallel", mode: "both", wantErr: false},
		{name: "unknown mode", mode: "mesh", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlText := "version: \"1\"\nnetwork:\n  mode: " + tt.mode + "\n"
			if tt.mode == "" {
				yamlText = "version: \"1\"\n"
			}
			_, err := ParseRepo([]byte(yamlText))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRepo(mode=%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "network.mode") {
				t.Errorf("error %q must mention network.mode", err)
			}
		})
	}
}

func TestParseUser_SecretValues(t *testing.T) {
	user, err := ParseUser([]byte(`
secrets:
  ai_token: "tok-literal-123"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if user.Secrets["ai_token"] != "tok-literal-123" {
		t.Errorf("secret ai_token = %q, want literal value", user.Secrets["ai_token"])
	}
}

func TestValidateUser_EmptySecretNameRejected(t *testing.T) {
	_, err := ParseUser([]byte("secrets:\n  \"\": value\n"))
	if err == nil {
		t.Fatal("empty secret name must be rejected")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Errorf("error %q must mention secrets", err)
	}
}

func TestValidateUser_DuplicateSecretNameRejected(t *testing.T) {
	_, err := ParseUser([]byte(`
secret_sources:
  ai_token:
    cmd: [op, read, x]
secrets:
  ai_token: /etc/host-file
`))
	if err == nil {
		t.Fatal("secret defined in both secret_sources and secrets must be rejected")
	}
	if !strings.Contains(err.Error(), "ai_token") {
		t.Errorf("error must name the clashing secret: %v", err)
	}
}

func TestValidateUser_EmptySecretPathRejected(t *testing.T) {
	_, err := ParseUser([]byte("secrets:\n  ai_token: \"\"\n"))
	if err == nil {
		t.Fatal("empty host path must be rejected")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Errorf("error %q must mention secrets", err)
	}
}

func TestParseRepo_EnvInherit(t *testing.T) {
	repo, err := ParseRepo([]byte(`
version: "1"
env:
  inherit:
    - LANG
    - TERM
  inherit_all: true
`))
	if err != nil {
		t.Fatalf("parse repo with env.inherit failed: %v", err)
	}
	if len(repo.Env.Inherit) != 2 || repo.Env.Inherit[0] != "LANG" || repo.Env.Inherit[1] != "TERM" {
		t.Errorf("repo.Env.Inherit = %v, want [LANG TERM]", repo.Env.Inherit)
	}
	if !repo.Env.InheritAll {
		t.Errorf("repo.Env.InheritAll = false, want true")
	}
}

func TestParseUser_EnvInherit(t *testing.T) {
	user, err := ParseUser([]byte(`
env:
  inherit:
    - COLORTERM
  inherit_all: true
repos:
  "/some/path":
    env:
      inherit:
        - LC_ALL
`))
	if err != nil {
		t.Fatalf("parse user with env.inherit failed: %v", err)
	}
	if len(user.Env.Inherit) != 1 || user.Env.Inherit[0] != "COLORTERM" {
		t.Errorf("user.Env.Inherit = %v, want [COLORTERM]", user.Env.Inherit)
	}
	if !user.Env.InheritAll {
		t.Errorf("user.Env.InheritAll = false, want true")
	}
	override := user.Repos["/some/path"]
	if len(override.Env.Inherit) != 1 || override.Env.Inherit[0] != "LC_ALL" {
		t.Errorf("override.Env.Inherit = %v, want [LC_ALL]", override.Env.Inherit)
	}
}

func TestParseEnv_InheritRejectsEquals(t *testing.T) {
	tests := []struct {
		name     string
		isUser   bool
		yamlText string
		wantErr  string
	}{
		{
			name: "repo inherit contains equals",
			yamlText: `
version: "1"
env:
  inherit:
    - FOO=bar
`,
			wantErr: "FOO=bar",
		},
		{
			name: "repo inherit contains empty string",
			yamlText: `
version: "1"
env:
  inherit:
    - ""
`,
			wantErr: "empty",
		},
		{
			name:   "user inherit contains equals",
			isUser: true,
			yamlText: `
env:
  inherit:
    - BAZ=123
`,
			wantErr: "BAZ=123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.isUser {
				_, err = ParseUser([]byte(tt.yamlText))
			} else {
				_, err = ParseRepo([]byte(tt.yamlText))
			}
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParsePublishFlag(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantHostIP  string
		wantGuest   int
		wantHost    int
		wantDynamic bool
		wantErr     string
	}{
		{name: "plain port", input: "8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 8080},
		{name: "host and container port", input: "8080:80", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		{name: "same host and container port", input: "8080:8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 8080},
		{name: "empty ip host and container", input: ":8080:8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 8080},
		{name: "empty ip host and different container", input: ":8080:80", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		{name: "loopback ip host and container", input: "127.0.0.1:8080:80", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		{name: "loopback ip same host and container", input: "127.0.0.1:8080:8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 8080},
		{name: "localhost host and container", input: "localhost:8080:80", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		{name: "dynamic port with colon", input: ":8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "dynamic port with double colon", input: "::8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "dynamic port with ip", input: "127.0.0.1::8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "dynamic port with zero host", input: "0:8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "dynamic port with ip and zero host", input: "127.0.0.1:0:8080", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "ipv6 loopback with host and container", input: "[::1]:8080:80", wantHostIP: "::1", wantGuest: 80, wantHost: 8080},
		{name: "ipv6 loopback dynamic", input: "[::1]::8080", wantHostIP: "::1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "ipv6 loopback plain container", input: "[::1]:8080", wantHostIP: "::1", wantGuest: 8080, wantHost: 0, wantDynamic: true},
		{name: "tcp protocol suffix on plain port", input: "8080/tcp", wantHostIP: "127.0.0.1", wantGuest: 8080, wantHost: 8080},
		{name: "tcp protocol suffix on host:container", input: "8080:80/tcp", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		{name: "tcp protocol suffix on ip:host:container", input: "127.0.0.1:8080:80/TCP", wantHostIP: "127.0.0.1", wantGuest: 80, wantHost: 8080},
		// Custom / Any-IP bindings (0.0.0.0, LAN IPs, IPv6)
		{name: "all interfaces 0.0.0.0", input: "0.0.0.0:8080:80", wantHostIP: "0.0.0.0", wantGuest: 80, wantHost: 8080},
		{name: "all interfaces 0.0.0.0 in bracket", input: "[0.0.0.0]:8080:80", wantHostIP: "0.0.0.0", wantGuest: 80, wantHost: 8080},
		{name: "all interfaces ipv6 :: in bracket", input: "[::]:8080:80", wantHostIP: "::", wantGuest: 80, wantHost: 8080},
		{name: "non-loopback ip", input: "192.168.1.1:8080:80", wantHostIP: "192.168.1.1", wantGuest: 80, wantHost: 8080},
		{name: "non-loopback ip in bracket", input: "[192.168.1.1]:8080:80", wantHostIP: "192.168.1.1", wantGuest: 80, wantHost: 8080},
		// Errors
		{name: "empty", input: "", wantErr: "empty"},
		{name: "invalid non-numeric", input: "abc", wantErr: "invalid"},
		{name: "invalid host port", input: "abc:80", wantErr: "invalid"},
		{name: "invalid container port", input: "80:abc", wantErr: "invalid"},
		{name: "invalid ip host port", input: "127.0.0.1:abc:80", wantErr: "invalid"},
		{name: "invalid ip container port", input: "127.0.0.1:80:abc", wantErr: "invalid"},
		{name: "invalid host ip", input: "999.999.999.999:8080:80", wantErr: "invalid host ip"},
		{name: "port 0 as container port", input: "0", wantErr: "out of range"},
		{name: "port 0 as container in mapping", input: "8080:0", wantErr: "out of range"},
		{name: "container port out of range", input: "70000", wantErr: "out of range"},
		{name: "host port out of range", input: "70000:80", wantErr: "out of range"},
		{name: "unsupported udp protocol", input: "8080/udp", wantErr: "only tcp is supported"},
		{name: "unsupported sctp protocol", input: "8080/sctp", wantErr: "only tcp is supported"},
		{name: "too many colon segments", input: "1:2:3:4", wantErr: "invalid port spec"},
		{name: "unclosed bracket", input: "[::1:8080", wantErr: "missing closing bracket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParsePublishFlag(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParsePublishFlag(%q) expected error containing %q, got nil", tt.input, tt.wantErr)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
					t.Fatalf("ParsePublishFlag(%q) error %q does not contain %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePublishFlag(%q) unexpected error: %v", tt.input, err)
			}
			if spec.Guest != tt.wantGuest || spec.Host != tt.wantHost || spec.Dynamic != tt.wantDynamic || (tt.wantHostIP != "" && spec.HostIP != tt.wantHostIP) {
				t.Errorf("ParsePublishFlag(%q) = %+v, want HostIP=%q, Guest=%d, Host=%d, Dynamic=%v",
					tt.input, spec, tt.wantHostIP, tt.wantGuest, tt.wantHost, tt.wantDynamic)
			}
		})
	}
}

func TestParseForwardHostFlag(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantGuestPort  int
		wantTargetHost string
		wantTargetPort int
		wantErr        string
	}{
		{name: "full 3 segments", input: "2345:127.0.0.1:1234", wantGuestPort: 2345, wantTargetHost: "127.0.0.1", wantTargetPort: 1234},
		{name: "full with hostname", input: "2345:db.corp.internal:5432", wantGuestPort: 2345, wantTargetHost: "db.corp.internal", wantTargetPort: 5432},
		{name: "full with ipv6 in brackets", input: "2345:[::1]:1234", wantGuestPort: 2345, wantTargetHost: "::1", wantTargetPort: 1234},
		{name: "full with localhost", input: "2345:localhost:1234", wantGuestPort: 2345, wantTargetHost: "localhost", wantTargetPort: 1234},
		{name: "2 segments host and port", input: "db.corp.internal:5432", wantGuestPort: 5432, wantTargetHost: "db.corp.internal", wantTargetPort: 5432},
		{name: "2 segments ipv4 and port", input: "127.0.0.1:5432", wantGuestPort: 5432, wantTargetHost: "127.0.0.1", wantTargetPort: 5432},
		{name: "2 segments ipv6 in brackets and port", input: "[::1]:5432", wantGuestPort: 5432, wantTargetHost: "::1", wantTargetPort: 5432},
		{name: "single port assumes localhost", input: "5432", wantGuestPort: 5432, wantTargetHost: "127.0.0.1", wantTargetPort: 5432},
		// Errors
		{name: "empty", input: "", wantErr: "empty"},
		{name: "invalid guest port", input: "abc:127.0.0.1:1234", wantErr: "invalid"},
		{name: "invalid target port", input: "2345:127.0.0.1:abc", wantErr: "invalid"},
		{name: "guest port out of range", input: "70000:127.0.0.1:1234", wantErr: "out of range"},
		{name: "target port out of range", input: "2345:127.0.0.1:70000", wantErr: "out of range"},
		{name: "empty target host", input: "2345::1234", wantErr: "target host"},
		{name: "too many segments", input: "1:2:3:4", wantErr: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseForwardHostFlag(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseForwardHostFlag(%q) expected error containing %q, got nil", tt.input, tt.wantErr)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
					t.Fatalf("ParseForwardHostFlag(%q) error %q does not contain %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseForwardHostFlag(%q) unexpected error: %v", tt.input, err)
			}
			if spec.GuestPort != tt.wantGuestPort || spec.TargetHost != tt.wantTargetHost || spec.TargetPort != tt.wantTargetPort {
				t.Errorf("ParseForwardHostFlag(%q) = %+v, want GuestPort=%d, TargetHost=%q, TargetPort=%d",
					tt.input, spec, tt.wantGuestPort, tt.wantTargetHost, tt.wantTargetPort)
			}
		})
	}
}

func TestParseRepo_ForwardHosts(t *testing.T) {
	yamlText := `
version: "1"
ports:
  - host_ip: "0.0.0.0"
    host_port: 8080
    guest_port: 80
forward_hosts:
  - guest_port: 2345
    target_host: "127.0.0.1"
    target_port: 1234
  - "5432:db.corp.internal:5432"
`
	repo, err := ParseRepo([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseRepo failed: %v", err)
	}
	if len(repo.Ports) != 1 {
		t.Fatalf("len(repo.Ports) = %d, want 1", len(repo.Ports))
	}
	if repo.Ports[0].HostIP != "0.0.0.0" || repo.Ports[0].Host != 8080 || repo.Ports[0].Guest != 80 {
		t.Errorf("repo.Ports[0] = %+v, want HostIP=0.0.0.0, Host=8080, Guest=80", repo.Ports[0])
	}
	if len(repo.ForwardHosts) != 2 {
		t.Fatalf("len(repo.ForwardHosts) = %d, want 2", len(repo.ForwardHosts))
	}
	if repo.ForwardHosts[0].GuestPort != 2345 || repo.ForwardHosts[0].TargetHost != "127.0.0.1" || repo.ForwardHosts[0].TargetPort != 1234 {
		t.Errorf("repo.ForwardHosts[0] = %+v, want GuestPort=2345, TargetHost=127.0.0.1, TargetPort=1234", repo.ForwardHosts[0])
	}
	if repo.ForwardHosts[1].GuestPort != 5432 || repo.ForwardHosts[1].TargetHost != "db.corp.internal" || repo.ForwardHosts[1].TargetPort != 5432 {
		t.Errorf("repo.ForwardHosts[1] = %+v, want GuestPort=5432, TargetHost=db.corp.internal, TargetPort=5432", repo.ForwardHosts[1])
	}
}

func TestParseRepo_TrustAnchors(t *testing.T) {
	yamlText := `
version: "1"
trust_anchors:
  - justfile
  - Makefile
  - scripts/build.sh
`
	repo, err := ParseRepo([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseRepo failed: %v", err)
	}
	if len(repo.TrustAnchors) != 3 {
		t.Fatalf("len(TrustAnchors) = %d, want 3", len(repo.TrustAnchors))
	}
	if repo.TrustAnchors[0] != "justfile" || repo.TrustAnchors[1] != "Makefile" || repo.TrustAnchors[2] != "scripts/build.sh" {
		t.Errorf("TrustAnchors = %v", repo.TrustAnchors)
	}
}

func TestValidateRepo_TrustAnchors_RejectsInvalid(t *testing.T) {
	tests := []struct {
		name     string
		yamlText string
		wantErr  string
	}{
		{
			name:     "empty anchor string",
			yamlText: "version: \"1\"\ntrust_anchors: [\" \"]\n",
			wantErr:  "empty",
		},
		{
			name:     "absolute path anchor",
			yamlText: "version: \"1\"\ntrust_anchors: [\"/etc/passwd\"]\n",
			wantErr:  "relative",
		},
		{
			name:     "path traversal parent",
			yamlText: "version: \"1\"\ntrust_anchors: [\"../outside.sh\"]\n",
			wantErr:  "escapes",
		},
		{
			name:     "nested path traversal parent",
			yamlText: "version: \"1\"\ntrust_anchors: [\"foo/../../outside.sh\"]\n",
			wantErr:  "escapes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRepo([]byte(tt.yamlText))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEffectiveTrustAnchors(t *testing.T) {
	tempDir := t.TempDir()
	justfilePath := filepath.Join(tempDir, "justfile")
	if err := os.WriteFile(justfilePath, []byte("build:\n\techo ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	makefilePath := filepath.Join(tempDir, "Makefile")
	if err := os.WriteFile(makefilePath, []byte("all:\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		repo     *Repo
		repoDir  string
		wantList []string
	}{
		{
			name:     "no anchors, no delegation",
			repo:     &Repo{Version: "1"},
			repoDir:  tempDir,
			wantList: nil,
		},
		{
			name: "explicit anchors",
			repo: &Repo{
				Version:      "1",
				TrustAnchors: []string{"Makefile"},
			},
			repoDir:  tempDir,
			wantList: []string{"Makefile"},
		},
		{
			name: "auto justfile detection on exact task",
			repo: &Repo{
				Version: "1",
				DelegatedTasks: DelegatedTasks{
					Exact: []string{"build"},
				},
			},
			repoDir:  tempDir,
			wantList: []string{"justfile"},
		},
		{
			name: "auto justfile detection on prefixes task",
			repo: &Repo{
				Version: "1",
				DelegatedTasks: DelegatedTasks{
					Prefixes: []string{"test-"},
				},
			},
			repoDir:  tempDir,
			wantList: []string{"justfile"},
		},
		{
			name: "explicit anchor and auto justfile merged and sorted",
			repo: &Repo{
				Version:      "1",
				TrustAnchors: []string{"Makefile", "justfile"},
				DelegatedTasks: DelegatedTasks{
					Exact: []string{"build"},
				},
			},
			repoDir:  tempDir,
			wantList: []string{"Makefile", "justfile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EffectiveTrustAnchors(tt.repo, tt.repoDir)
			if err != nil {
				t.Fatalf("EffectiveTrustAnchors error: %v", err)
			}
			if len(got) != len(tt.wantList) {
				t.Fatalf("len(got) = %d, want %d (got: %v, want: %v)", len(got), len(tt.wantList), got, tt.wantList)
			}
			for i := range got {
				if got[i] != tt.wantList[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.wantList[i])
				}
			}
		})
	}
}

func TestUserConfig_SeccompToggleParsed(t *testing.T) {
	tests := []struct {
		name        string
		yamlText    string
		wantSeccomp string
		wantErr     bool
	}{
		{
			name:        "empty security block defaults",
			yamlText:    "security:\n  landlock: auto\n",
			wantSeccomp: "",
			wantErr:     false,
		},
		{
			name:        "explicit seccomp auto",
			yamlText:    "security:\n  seccomp: auto\n",
			wantSeccomp: "auto",
			wantErr:     false,
		},
		{
			name:        "explicit seccomp on",
			yamlText:    "security:\n  seccomp: on\n",
			wantSeccomp: "on",
			wantErr:     false,
		},
		{
			name:        "explicit seccomp off",
			yamlText:    "security:\n  seccomp: off\n",
			wantSeccomp: "off",
			wantErr:     false,
		},
		{
			name:     "invalid seccomp value",
			yamlText: "security:\n  seccomp: disabled\n",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := ParseUser([]byte(tt.yamlText))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && user.Security.Seccomp != tt.wantSeccomp {
				t.Errorf("user.Security.Seccomp = %q, want %q", user.Security.Seccomp, tt.wantSeccomp)
			}
		})
	}
}

func TestRepoConfig_SeccompFieldRejected(t *testing.T) {
	repoYAML := `
version: "1"
security:
  seccomp: off
`
	_, err := ParseRepo([]byte(repoYAML))
	if err == nil {
		t.Fatal("repo config with security.seccomp must be rejected")
	}
	if !strings.Contains(err.Error(), "security") && !strings.Contains(err.Error(), "seccomp") {
		t.Errorf("error %q must mention unknown field security/seccomp", err)
	}
}

func TestParseRepo_PathsExtra(t *testing.T) {
	yamlText := `
version: "1"
paths:
  extra:
    - node_modules/.bin
    - vendor/bin
    - /opt/custom/bin
`
	repo, err := ParseRepo([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseRepo() error = %v", err)
	}
	if len(repo.Paths.Extra) != 3 {
		t.Fatalf("repo.Paths.Extra length = %d, want 3", len(repo.Paths.Extra))
	}
	want := []string{"node_modules/.bin", "vendor/bin", "/opt/custom/bin"}
	for i, w := range want {
		if repo.Paths.Extra[i] != w {
			t.Errorf("repo.Paths.Extra[%d] = %q, want %q", i, repo.Paths.Extra[i], w)
		}
	}
}

func TestParseRepo_PathsExtra_RejectsEmpty(t *testing.T) {
	yamlText := `
version: "1"
paths:
  extra:
    - "  "
`
	_, err := ParseRepo([]byte(yamlText))
	if err == nil {
		t.Fatal("ParseRepo() with empty paths.extra entry must fail")
	}
	if !strings.Contains(err.Error(), "paths.extra") {
		t.Errorf("error %q must mention paths.extra", err)
	}
}

func TestParseRepo_PathsRejectsHostFields(t *testing.T) {
	yamlText := `
version: "1"
paths:
  storage_base: /var/lib/containers/storage
`
	_, err := ParseRepo([]byte(yamlText))
	if err == nil {
		t.Fatal("repo config with paths.storage_base must be rejected")
	}
	if !strings.Contains(err.Error(), "storage_base") {
		t.Errorf("error %q must mention storage_base", err)
	}
}

func TestParseUser_PathsExtra(t *testing.T) {
	yamlText := `
paths:
  storage_base: /custom/storage
  extra:
    - /opt/tools/bin
    - ~/.local/bin
repos:
  "~/work/*":
    paths:
      extra:
        - /opt/work/bin
`
	user, err := ParseUser([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseUser() error = %v", err)
	}
	if len(user.Paths.Extra) != 2 {
		t.Fatalf("user.Paths.Extra length = %d, want 2", len(user.Paths.Extra))
	}
	if user.Paths.Extra[0] != "/opt/tools/bin" || user.Paths.Extra[1] != "~/.local/bin" {
		t.Errorf("user.Paths.Extra = %v", user.Paths.Extra)
	}
	repoOverride, ok := user.Repos["~/work/*"]
	if !ok || repoOverride.Paths == nil {
		t.Fatalf("repo override ~/work/* paths missing")
	}
	if len(repoOverride.Paths.Extra) != 1 || repoOverride.Paths.Extra[0] != "/opt/work/bin" {
		t.Errorf("repo override paths.extra = %v", repoOverride.Paths.Extra)
	}
}

func TestParseUser_PathsExtra_RejectsEmpty(t *testing.T) {
	yamlText := `
paths:
  extra:
    - ""
`
	_, err := ParseUser([]byte(yamlText))
	if err == nil {
		t.Fatal("ParseUser() with empty paths.extra entry must fail")
	}
	if !strings.Contains(err.Error(), "paths.extra") {
		t.Errorf("error %q must mention paths.extra", err)
	}
}

func TestParseRepo_PathsPrependAndAppend(t *testing.T) {
	yamlText := `
version: "1"
paths:
  prepend:
    - node_modules/.bin
    - vendor/bin
  append:
    - /opt/fallback/bin
`
	repo, err := ParseRepo([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseRepo() error = %v", err)
	}
	if len(repo.Paths.Prepend) != 2 {
		t.Fatalf("repo.Paths.Prepend length = %d, want 2", len(repo.Paths.Prepend))
	}
	if repo.Paths.Prepend[0] != "node_modules/.bin" || repo.Paths.Prepend[1] != "vendor/bin" {
		t.Errorf("repo.Paths.Prepend = %v", repo.Paths.Prepend)
	}
	if len(repo.Paths.Append) != 1 || repo.Paths.Append[0] != "/opt/fallback/bin" {
		t.Errorf("repo.Paths.Append = %v", repo.Paths.Append)
	}
}

func TestParseRepo_PathsPrependAppend_RejectsEmpty(t *testing.T) {
	t.Run("prepend empty", func(t *testing.T) {
		yamlText := `version: "1"
paths:
  prepend: [""]
`
		_, err := ParseRepo([]byte(yamlText))
		if err == nil || !strings.Contains(err.Error(), "paths.prepend") {
			t.Errorf("expected paths.prepend error, got %v", err)
		}
	})

	t.Run("append empty", func(t *testing.T) {
		yamlText := `version: "1"
paths:
  append: ["   "]
`
		_, err := ParseRepo([]byte(yamlText))
		if err == nil || !strings.Contains(err.Error(), "paths.append") {
			t.Errorf("expected paths.append error, got %v", err)
		}
	})
}

func TestParseUser_PathsPrependAndAppend(t *testing.T) {
	yamlText := `
paths:
  prepend:
    - /opt/user-prepend
  append:
    - /opt/user-append
repos:
  "~/work/*":
    paths:
      prepend:
        - /opt/work-prepend
      append:
        - /opt/work-append
`
	user, err := ParseUser([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseUser() error = %v", err)
	}
	if len(user.Paths.Prepend) != 1 || user.Paths.Prepend[0] != "/opt/user-prepend" {
		t.Errorf("user.Paths.Prepend = %v", user.Paths.Prepend)
	}
	if len(user.Paths.Append) != 1 || user.Paths.Append[0] != "/opt/user-append" {
		t.Errorf("user.Paths.Append = %v", user.Paths.Append)
	}
	repoOverride, ok := user.Repos["~/work/*"]
	if !ok || repoOverride.Paths == nil {
		t.Fatalf("repo override ~/work/* paths missing")
	}
	if len(repoOverride.Paths.Prepend) != 1 || repoOverride.Paths.Prepend[0] != "/opt/work-prepend" {
		t.Errorf("repo override paths.prepend = %v", repoOverride.Paths.Prepend)
	}
	if len(repoOverride.Paths.Append) != 1 || repoOverride.Paths.Append[0] != "/opt/work-append" {
		t.Errorf("repo override paths.append = %v", repoOverride.Paths.Append)
	}
}

func TestParseUser_PathsPrependAppend_RejectsEmpty(t *testing.T) {
	t.Run("prepend empty", func(t *testing.T) {
		yamlText := `paths:
  prepend: [""]
`
		_, err := ParseUser([]byte(yamlText))
		if err == nil || !strings.Contains(err.Error(), "paths.prepend") {
			t.Errorf("expected paths.prepend error, got %v", err)
		}
	})

	t.Run("append empty", func(t *testing.T) {
		yamlText := `paths:
  append: ["  "]
`
		_, err := ParseUser([]byte(yamlText))
		if err == nil || !strings.Contains(err.Error(), "paths.append") {
			t.Errorf("expected paths.append error, got %v", err)
		}
	})
}
