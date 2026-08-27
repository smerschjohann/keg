// Package config loads, validates and merges keg configuration.
//
// Two layers exist: the per-repo .keg.yaml (versioned, no host paths)
// and the machine-local user config ($XDG_CONFIG_HOME/keg/config.yaml).
// See CONCEPT.md §4.8/§5 for the schema and merge semantics.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SupportedVersion is the only repo config schema version keg accepts.
const SupportedVersion = "1"

// BuiltinTemplates are the supported language templates (CONCEPT.md §4.6).
var BuiltinTemplates = map[string]bool{
	"go": true, "golang": true, "java": true, "node": true, "python": true,
}

// Duration is a yaml-friendly time.Duration accepting strings like "5m".
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses durations from scalar nodes ("30s", "1m", plain
// integers are treated as seconds to catch config mistakes early? no —
// require explicit units).
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a string with unit, e.g. \"30s\"")
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	d.Duration = parsed
	return nil
}

// MountMode is the bind mode of a custom mount.
type MountMode string

// Mount modes for custom binds.
const (
	MountRO        MountMode = "ro"
	MountRW        MountMode = "rw"
	MountDev       MountMode = "dev"
	MountTmpfs     MountMode = "tmpfs"
	MountEphemeral MountMode = "ephemeral"
	MountDisk      MountMode = "disk"
)

// Valid reports whether the mode is known.
func (m MountMode) Valid() bool {
	switch m {
	case MountRO, MountRW, MountDev, MountTmpfs, MountEphemeral, MountDisk:
		return true
	}
	return false
}

// EnvSpec is first-class environment control for the sandbox.
type EnvSpec struct {
	Unset      []string          `yaml:"unset"`
	Set        map[string]string `yaml:"set"`
	Inherit    []string          `yaml:"inherit"`
	InheritAll bool              `yaml:"inherit_all"`
}

// Mount is an additional filesystem bind declared by the repo.
type Mount struct {
	Src         string    `yaml:"src"`
	Dest        string    `yaml:"dest"`
	Mode        MountMode `yaml:"mode"`
	OverlayRW   string    `yaml:"-"` // host dir for disk overlay upper (OverlayDisk)
	OverlayWork string    `yaml:"-"` // host dir for disk overlay work (OverlayDisk)
}

// SecretRef declares the need for a secret defined in the user config.
type SecretRef struct {
	Name string `yaml:"name"`
	Env  string `yaml:"env"` // optional: also set <Env>=/run/secrets/<Name>
}

// PortSpec is one entry of the port back-channel (CONCEPT.md §4.9).
type PortSpec struct {
	Name    string `yaml:"name"`
	Guest   int    `yaml:"guest"` // parsed from string forms too
	Host    int    `yaml:"host"`
	Dynamic bool   `yaml:"dynamic"`
}

// UnmarshalYAML accepts "3000", "src:dst" and struct forms.
func (p *PortSpec) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.MappingNode {
		var raw struct {
			Name    string `yaml:"name"`
			Port    int    `yaml:"port"`
			Dynamic bool   `yaml:"dynamic"`
		}
		if err := value.Decode(&raw); err != nil {
			return err
		}
		p.Name, p.Dynamic = raw.Name, raw.Dynamic
		p.Guest, p.Host = raw.Port, raw.Port
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("port spec must be a string or mapping")
	}
	s := value.Value
	guest, host, err := parsePortString(s)
	if err != nil {
		return err
	}
	p.Guest, p.Host = guest, host
	return nil
}

// Network configures egress policy.
type Network struct {
	Mode string `yaml:"mode"` // "" | "proxy" | "transparent" | "both"
	// "both" runs the explicit HTTP-proxy path (HTTP(S)_PROXY env) and the
	// transparent SNI path in parallel: both routes converge on the same
	// host-side whitelist proxy, so the policy stays identical.
	DNS DNS `yaml:"dns"`
	// SNIDomains: name-based policy — CONNECT (proxy mode) resp. TLS SNI
	// (transparent mode, TCP/443 only).
	SNIDomains []string `yaml:"sni_domains"`
	// TCPEndpoints: IP/port-based policy for raw TCP via nftables REDIRECT
	// + DNS-correlation (transparent mode only); e.g. database connections.
	TCPEndpoints []TCPEndpoint `yaml:"tcp_endpoints"`
}

// TCPEndpoint whitelists one raw-TCP destination by name (resolved via the
// keg resolver, correlated to IPs) and pinned ports.
type TCPEndpoint struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports"`
}

// AllowedTCPEndpoint whitelists a raw TCP target ("host:port").
type AllowedTCPEndpoint struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// DNS holds static hosts mappings and upstream resolver settings.
type DNS struct {
	Enabled  bool              `yaml:"enabled"`
	Upstream string            `yaml:"upstream"`
	Hosts    map[string]string `yaml:"hosts"`
}

// RawRule is a delegation rule for real host binaries (CONCEPT.md §4.5).
type RawRule struct {
	Cmd                   string   `yaml:"cmd"`
	Subcommands           []string `yaml:"subcommands"`
	OptsWithValue         []string `yaml:"opts_with_value"`
	Flags                 []string `yaml:"flags"`
	AllowOptValueForm     bool     `yaml:"allow_opt_value_form"`
	ForbiddenArgsMatching []string `yaml:"forbidden_args_matching"`
}

// DelegatedTasks is the host-only task whitelist of the repo.
type DelegatedTasks struct {
	Exact    []string  `yaml:"exact"`
	Prefixes []string  `yaml:"prefixes"`
	Raw      []RawRule `yaml:"raw"`
}

// Repo mirrors .keg.yaml.
type Repo struct {
	Version        string            `yaml:"version"`
	Vars           map[string]string `yaml:"vars"`
	Templates      []string          `yaml:"templates"`
	Env            EnvSpec           `yaml:"env"`
	BwrapArgs      []string          `yaml:"bwrap_args"`
	Mounts         []Mount           `yaml:"mounts"`
	Secrets        []SecretRef       `yaml:"secrets"`
	Ports          []PortSpec        `yaml:"ports"`
	Network        Network           `yaml:"network"`
	DelegatedTasks DelegatedTasks    `yaml:"delegated_tasks"`
	TrustAnchors   []string          `yaml:"trust_anchors"`
}

// Paths are machine-local base directories (user config only).
type Paths struct {
	StorageBase  string `yaml:"storage_base"`
	TmpBase      string `yaml:"tmp_base"`
	GoModCache   string `yaml:"go_mod_cache"`
	GoBuildCache string `yaml:"go_build_cache"`
}

// RunnerCfg holds delegation settings and local extra allowlists.
type RunnerCfg struct {
	JustBin       string    `yaml:"just_bin"`
	ExtraExact    []string  `yaml:"extra_exact"`
	ExtraPrefixes []string  `yaml:"extra_prefixes"`
	ExtraRaw      []RawRule `yaml:"extra_raw"`
}

// TemplateEnv gates access to the host environment from repo templates.
type TemplateEnv struct {
	AllowEnv *bool `yaml:"allow_env"`
}

// ExecSource describes one vars_from_exec entry (user config only; the only
// place where keg runs programs to obtain values — THREAT_MODEL §8.4).
type ExecSource struct {
	Cmd     []string `yaml:"cmd"`
	Cache   string   `yaml:"cache"` // session (default) | none
	Timeout Duration `yaml:"timeout"`
}

// Security toggles that weaken isolation need explicit consent.
type Security struct {
	AllowWeakBwrap *bool  `yaml:"allow_weak_bwrap"`
	Landlock       string `yaml:"landlock"` // auto | on | off
	Seccomp        string `yaml:"seccomp"`  // auto | on | off
}

// LogCfg optionally directs audit output to a file.
type LogCfg struct {
	AuditFile string `yaml:"audit_file"`
}

// SecretSource is one secret_sources entry (mechanism lives in user config).
// Always (default false) makes the secret available in EVERY sandbox, even
// when no repo declares the need — see CONCEPT.md §4.7.
// If Always is true the source is only reachable via secret_sources, never
// via the host-file secrets map (that map carries no always flag).
type SecretSource struct {
	Cmd            []string `yaml:"cmd"`
	Interval       Duration `yaml:"interval"`
	Timeout        Duration `yaml:"timeout"`
	OnRefreshError string   `yaml:"on_refresh_error"` // keep (default) | fail
	Always         bool     `yaml:"always"`           // inject into every sandbox
}

// RepoOverride is the per-target-repo section of the user config. It shares
// the structure of the global scope but never introduces new schema.
type RepoOverride struct {
	Paths   *Paths            `yaml:"paths"`
	Runner  *RunnerOverride   `yaml:"runner"`
	Vars    map[string]string `yaml:"vars"`
	Mounts  []Mount           `yaml:"mounts"`
	Network Network           `yaml:"network"`
	Env     EnvSpec           `yaml:"env"`
	// Secrets is an additional need list for this target repo: entries are
	// unioned with the repo's own .keg.yaml `secrets:` declarations and
	// must be resolvable via the user config's secret_sources / secrets map.
	Secrets []SecretRef `yaml:"secrets"`
}

// RunnerOverride carries only the additive allowlist parts.
type RunnerOverride struct {
	JustBin       string    `yaml:"just_bin"`
	ExtraExact    []string  `yaml:"extra_exact"`
	ExtraPrefixes []string  `yaml:"extra_prefixes"`
	ExtraRaw      []RawRule `yaml:"extra_raw"`
}

// User mirrors ~/.config/keg/config.yaml.
type User struct {
	Paths         Paths                   `yaml:"paths"`
	Runner        RunnerCfg               `yaml:"runner"`
	Vars          map[string]string       `yaml:"vars"`
	TemplateEnv   TemplateEnv             `yaml:"template_env"`
	VarsFromExec  map[string]ExecSource   `yaml:"vars_from_exec"`
	Security      Security                `yaml:"security"`
	Log           LogCfg                  `yaml:"log"`
	SecretSources map[string]SecretSource `yaml:"secret_sources"`
	// InjectNeeds carries the secret need refs contributed by the matched
	// repos[] override after MergeUsers. It is never parsed directly from the
	// global YAML (the global `secrets:` key is the host-file mechanism map);
	// MergeUsers fills it from the per-repo RepoOverride.Secrets list.
	InjectNeeds []SecretRef `yaml:"-"`
	// Secrets maps secret names to existing HOST FILES: a repo may
	// reference the name via its `secrets:` list and the file is mounted
	// read-only at /run/secrets/<name>. Paths support ~ and $VAR expansion.
	// A name must not also appear in secret_sources (exactly one origin).
	Secrets map[string]string       `yaml:"secrets"`
	Mounts  []Mount                 `yaml:"mounts"`
	Network Network                 `yaml:"network"`
	Env     EnvSpec                 `yaml:"env"`
	Repos   map[string]RepoOverride `yaml:"repos"`
}

// ParseRepo decodes and validates a repo config from bytes (strict: unknown
// fields are errors).
func ParseRepo(data []byte) (*Repo, error) {
	var repo Repo
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&repo); err != nil {
		return nil, fmt.Errorf("repo config: %w", err)
	}
	if err := repo.validate(); err != nil {
		return nil, err
	}
	return &repo, nil
}

// LoadRepo reads and parses <repoRoot>/.keg.yaml or the given path.
func LoadRepo(path string) (*Repo, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from CLI/config resolution
	if err != nil {
		return nil, fmt.Errorf("load repo config %s: %w", path, err)
	}
	return ParseRepo(data)
}

// ParseUser decodes a user config from bytes (strict).
func ParseUser(data []byte) (*User, error) {
	var user User
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&user); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("user config: %w", err)
	}
	if err := user.validate(); err != nil {
		return nil, err
	}
	return &user, nil
}

// DefaultUserPath returns $XDG_CONFIG_HOME/keg/config.yaml (or the
// ~/.config fallback). The file may not exist; callers treat that as defaults-only.
func DefaultUserPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir + "/keg/config.yaml"
	}
	home, _ := os.UserHomeDir()
	return home + "/.config/keg/config.yaml"
}

func (r *Repo) validate() error {
	if r.Version == "" {
		return fmt.Errorf("repo config: field version is required")
	}
	if r.Version != SupportedVersion {
		return fmt.Errorf("repo config: unsupported version %q (want %q)", r.Version, SupportedVersion)
	}
	for _, tpl := range r.Templates {
		if !BuiltinTemplates[tpl] {
			return fmt.Errorf("repo config: unknown template %q (builtin: go, java, node, python)", tpl)
		}
	}
	for i, m := range r.Mounts {
		if m.Dest == "" && m.Mode != MountTmpfs {
			return fmt.Errorf("repo config: mount[%d]: dest required", i)
		}
		if m.Mode == "" {
			continue
		}
		if !m.Mode.Valid() {
			return fmt.Errorf("repo config: mount[%d]: invalid mode %q (ro|rw|dev|tmpfs)", i, m.Mode)
		}
	}
	for i, p := range r.Ports {
		if p.Guest <= 0 || p.Guest > 65535 || p.Host <= 0 || p.Host > 65535 {
			return fmt.Errorf("repo config: port spec %d (%v): port numbers must be in 1..65535", i, p)
		}
		if p.Dynamic && p.Name == "" {
			return fmt.Errorf("repo config: port spec %d: dynamic ports need a name", i)
		}
	}
	for i, raw := range r.DelegatedTasks.Raw {
		if len(raw.Subcommands) == 0 {
			return fmt.Errorf("repo config: delegated_tasks.raw[%d] (%s): subcommands must not be empty", i, raw.Cmd)
		}
	}
	switch r.Network.Mode {
	case "", "proxy", "transparent", "both":
	default:
		return fmt.Errorf("repo config: network.mode must be proxy|transparent|both")
	}
	for i, ep := range r.Network.TCPEndpoints {
		if ep.Host == "" {
			return fmt.Errorf("repo config: network.tcp_endpoints[%d]: host required", i)
		}
		if len(ep.Ports) == 0 {
			return fmt.Errorf("repo config: network.tcp_endpoints[%d] (%s): at least one port required", i, ep.Host)
		}
		for _, port := range ep.Ports {
			if port <= 0 || port > 65535 {
				return fmt.Errorf("repo config: network.tcp_endpoints[%d]: invalid port %d", i, port)
			}
		}
	}
	for name, src := range r.Network.DNS.Hosts {
		if src == "" {
			return fmt.Errorf("repo config: network.dns.hosts[%s]: empty target", name)
		}
	}
	for i, anchor := range r.TrustAnchors {
		trimmed := strings.TrimSpace(anchor)
		if trimmed == "" {
			return fmt.Errorf("repo config: trust_anchors[%d]: empty path", i)
		}
		if filepath.IsAbs(trimmed) {
			return fmt.Errorf("repo config: trust_anchors[%d] %q: path must be relative to repository root", i, anchor)
		}
		cleaned := filepath.Clean(trimmed)
		if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
			return fmt.Errorf("repo config: trust_anchors[%d] %q: path escapes repository root", i, anchor)
		}
	}
	if err := r.Env.validate("repo config"); err != nil {
		return err
	}
	return nil
}

// EffectiveTrustAnchors computes the full, sorted, and deduplicated list of relative
// trust anchor paths for a repository.
//
// All explicitly declared trust_anchors in .keg.yaml are included.
// Furthermore, if exact or prefix delegated tasks are defined:
//   - The root justfile ("justfile", "Justfile", ".justfile") in repoDir is automatically detected.
//   - All discovered and explicitly declared justfiles are recursively inspected for
//     import / !include statements to include all imported justfiles as trust anchors.
func EffectiveTrustAnchors(r *Repo, repoDir string) ([]string, error) {
	if r == nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	var list []string

	// 1. Explicitly configured trust anchors
	for _, a := range r.TrustAnchors {
		cleaned := filepath.Clean(strings.TrimSpace(a))
		if cleaned != "" && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
			if !seen[cleaned] {
				seen[cleaned] = true
				list = append(list, cleaned)
			}
			// If an explicit anchor is a justfile or contains imports, discover them
			collectJustfileAnchors(repoDir, cleaned, seen, &list)
		}
	}

	// 2. Auto-detect root justfile if delegated tasks use just
	if len(r.DelegatedTasks.Exact) > 0 || len(r.DelegatedTasks.Prefixes) > 0 {
		for _, name := range []string{"justfile", "Justfile", ".justfile"} {
			p := filepath.Join(repoDir, name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				collectJustfileAnchors(repoDir, name, seen, &list)
				break
			}
		}
	}

	slices.Sort(list)
	return list, nil
}

func (e *EnvSpec) validate(prefix string) error {
	for i, name := range e.Inherit {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s: env.inherit[%d]: empty name", prefix, i)
		}
		if strings.Contains(name, "=") {
			return fmt.Errorf("%s: env.inherit[%d] %q: variable name must not contain '='", prefix, i, name)
		}
	}
	for i, name := range e.Unset {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s: env.unset[%d]: empty name", prefix, i)
		}
		if strings.Contains(name, "=") {
			return fmt.Errorf("%s: env.unset[%d] %q: variable name must not contain '='", prefix, i, name)
		}
	}
	return nil
}

func (u *User) validate() error {
	if err := u.Env.validate("user config"); err != nil {
		return err
	}
	for name, hostPath := range u.Secrets {
		if name == "" {
			return fmt.Errorf("user config: secrets: entry with empty name")
		}
		if strings.TrimSpace(hostPath) == "" {
			return fmt.Errorf("user config: secrets[%s]: empty host path", name)
		}
		if _, clash := u.SecretSources[name]; clash {
			return fmt.Errorf("user config: secret %q defined in both secret_sources and secrets (choose one origin)", name)
		}
	}
	for name, dst := range u.SecretSources {
		switch dst.OnRefreshError {
		case "", "keep", "fail":
		default:
			return fmt.Errorf("user config: secret_sources[%s]: on_refresh_error must be keep|fail", name)
		}
		if len(dst.Cmd) == 0 {
			return fmt.Errorf("user config: secret_sources[%s]: cmd required", name)
		}
	}
	for repoPat, override := range u.Repos {
		if err := override.Env.validate(fmt.Sprintf("user config: repos[%s]", repoPat)); err != nil {
			return err
		}
		for _, ref := range override.Secrets {
			if ref.Name == "" {
				return fmt.Errorf("user config: repos[%s].secrets: entry with empty name", repoPat)
			}
		}
	}
	for name, src := range u.VarsFromExec {
		if len(src.Cmd) == 0 {
			return fmt.Errorf("user config: vars_from_exec[%s]: cmd required", name)
		}
		switch src.Cache {
		case "", "session", "none":
		default:
			return fmt.Errorf("user config: vars_from_exec[%s]: cache must be session|none", name)
		}
	}
	switch u.Security.Landlock {
	case "", "auto", "on", "off":
	default:
		return fmt.Errorf("user config: security.landlock must be auto|on|off")
	}
	switch u.Security.Seccomp {
	case "", "auto", "on", "off":
	default:
		return fmt.Errorf("user config: security.seccomp must be auto|on|off")
	}
	return nil
}
