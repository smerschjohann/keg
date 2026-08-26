// Package orchestrator builds bubblewrap argument lists and manages the
// sandbox lifecycle (socketpairs, reexec, cleanup). The argument builder is
// a pure, total function: no I/O, no global state — fully unit-testable.
package orchestrator

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/smerschjohann/keg/internal/config"
)

// FDProxy/FDDNS/FDRunner name the guest-side descriptors. bwrap (>= 0.11)
// passes cmd.ExtraFiles through verbatim starting at fd 3 — there is no
// --preserve-fds flag to request; inheritance is verified by
// TestSandboxFDInheritance (integration).
const (
	FDProxy  = 3 // Kanal A: egress proxy
	FDDNS    = 4 // Kanal B: DNS
	FDRunner = 5 // Kanal C: delegation runner
	// FDPreserved counts the extra FDs handed to bwrap via ExtraFiles.
	FDPreserved = 3
)

// Overlay selects the repository write mode.
type Overlay int

// Repository write modes.
const (
	OverlayPlain     Overlay = iota // rw bind of the repo
	OverlayEphemeral                // invisible tmpfs upper layer
	OverlayDisk                     // persistent on-disk layer
)

// String returns the CLI-facing name of the overlay mode.
func (o Overlay) String() string {
	switch o {
	case OverlayEphemeral:
		return "ephemeral"
	case OverlayDisk:
		return "disk"
	default:
		return "plain"
	}
}

// HostDeniedEnvVars are never passed into the sandbox: proxy settings and
// cloud credentials would leak either connectivity or secrets
// (THREAT_MODEL.md §8.2).
var HostDeniedEnvVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"OPENAI_API_KEY", "ANTHROPIC_API_KEY",
}

// weakBwrapFlags are isolation-weakening bwrap flags; they require explicit
// consent via security.allow_weak_bwrap in the user config.
var weakBwrapFlags = []string{
	"--share-net",
	"--dev-bind",
	"--unshare-net", "--unshare-netns", // listed for completeness; harmless
}

// Plan carries everything BuildArgs needs. All paths must already be
// resolved and template-expanded by the caller.
type Plan struct {
	RepoRoot    string // host == sandbox path of the repository
	SandboxHome string // tmpfs home inside the sandbox
	TmpDir      string // host instance temp dir
	ResolvConf  string // host path of the injected resolv.conf ("" = none)
	SecretDir   string // host dir ro-bound to /run/secrets ("" = none)

	// BwrapPath overrides the bubblewrap binary (tests inject a stub).
	BwrapPath string
	// KeepFDs lists additional descriptors (besides stdio and the channel
	// ends) that must survive into the sandbox; everything else is marked
	// close-on-exec before start.
	KeepFDs []int
	// Stdin/Stdout/Stderr wire the sandbox process (default: os.Std*).
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Mounts   []config.Mount    // custom binds, template-resolved
	EnvUnset []string          // additional vars to strip beyond HostDeniedEnvVars
	EnvSet   map[string]string // sandbox environment values

	BwrapArgs      []string // raw extra args, appended after all derived args
	AllowWeakBwrap bool     // security.allow_weak_bwrap from user config

	Overlay       Overlay
	DiskLayerRW   string // host dir with upper layer (OverlayDisk)
	DiskLayerWork string // host dir with work layer (OverlayDisk)

	// EgressWhitelist carries the repo's network.allowed_domains for the
	// host-side proxy server; empty disables channel A entirely.
	EgressWhitelist []string
	// EgressDNS carries channel-B policy; nil disables the DNS channel.
	EgressDNS *DNSConfig
	// HostsFile is a generated hosts file ro-bound to /etc/hosts so static
	// dns.hosts mappings resolve natively (glibc reads files first).
	HostsFile string
	// SelfExe is the host path of this binary. When set (Launch resolves it
	// automatically), BuildArgs routes the workload through the reexec'd
	// guest entrypoint: binds the binary read-only into the sandbox and
	// prefixes the command with the guest dispatch name.
	SelfExe string

	Command []string // command to exec after `--`
}

// DNSConfig is the host-side policy for egress channel B.
type DNSConfig struct {
	// Hosts are static mappings ("name" or "*.suffix" → IP) answered
	// authoritatively before whitelist and upstream.
	Hosts map[string]string
	// Whitelist gates which names may be forwarded upstream.
	Whitelist []string
	// Upstream resolver address ("host:port").
	Upstream string
}

// WeakFlags returns the isolation-weakening flags found in args.
func WeakFlags(args []string) []string {
	var found []string
	for i, a := range args {
		if slices.Contains(weakBwrapFlags, a) && !slices.Contains(found, a) {
			found = append(found, a)
			continue
		}
		// A dev-bind or plain bind targeting / exposes the host root.
		if a == "--bind" || a == "--dev-bind" {
			if i+2 < len(args) && isRootPath(args[i+1]) {
				if !slices.Contains(found, a+" /") {
					found = append(found, a+" /")
				}
			}
		}
	}
	return found
}

func isRootPath(p string) bool { return p == "/" }

// BuildArgs constructs the complete bwrap argument list. It errors when
// weak flags are present without consent.
func BuildArgs(p Plan) ([]string, error) {
	if weak := WeakFlags(p.BwrapArgs); len(weak) > 0 && !p.AllowWeakBwrap {
		return nil, fmt.Errorf(
			"bwrap_args contain isolation-weakening flag(s) %s — set security.allow_weak_bwrap: true in the user config to accept them",
			strings.Join(weak, ", "))
	}

	args := make([]string, 0, 64+len(p.BwrapArgs))
	args = append(args,
		"--unshare-all",
		// The network namespace is provided by the keg netns stage
		// wrapping bwrap (it owns that namespace and serves DNS :53 in
		// it), so bwrap retains it instead of creating a fresh one.
		"--share-net",
		// --disable-userns needs an explicit --unshare-user even though
		// --unshare-all implies it (bwrap 0.11 requirement).
		"--unshare-user",
		"--die-with-parent",
		"--disable-userns",
		"--proc", "/proc",
		"--dev", "/dev",
		// Fresh tmpfs over host /tmp: workload temp data never leaks.
		"--tmpfs", "/tmp",
	)

	// Base system layout (proven by run-sandbox.sh): real binds for /bin
	// and /lib work on merged-/usr systems and avoid symlink edge cases;
	// -try variants tolerate absent optional locations. /lib64 matters:
	// without it the dynamic loader is missing and every binary fails
	// with a misleading "No such file or directory". Everything NOT bound
	// here does not exist inside the sandbox (CONCEPT.md visibility model).
	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind", "/etc/passwd", "/etc/passwd",
		"--ro-bind-try", "/etc/alternatives", "/etc/alternatives", // linker for CGO
		"--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs",
		"--ro-bind-try", "/etc/pki", "/etc/pki",
		"--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--ro-bind-try", "/etc/crypto-policies", "/etc/crypto-policies",
	)

	// Repository write mode.
	switch p.Overlay {
	case OverlayEphemeral:
		// Writes land in an invisible tmpfs upper layer; the host repo
		// stays untouched (verified: bwrap 0.11 needs the lower dir as
		// --overlay-src).
		args = append(args, "--overlay-src", p.RepoRoot, "--tmp-overlay", p.RepoRoot)
	case OverlayDisk:
		// Persistent layer: writes go to the host-side RW dir. The lower
		// dir comes from --overlay-src; RW/WORK dirs must be on real disk
		// (ext4, e.g. /var/lib/containers/...) — overlayfs rejects upper
		// dirs on tmpfs inside user namespaces (see run-sandbox.sh).
		args = append(args, "--overlay-src", p.RepoRoot,
			"--overlay", p.DiskLayerRW, p.DiskLayerWork, p.RepoRoot)
	default:
		args = append(args, "--bind", p.RepoRoot, p.RepoRoot)
	}

	// Sandbox home as writable tmpfs, then start inside the repository.
	if p.SandboxHome != "" {
		args = append(args,
			"--tmpfs", p.SandboxHome,
			"--chdir", p.RepoRoot,
		)
	}

	// Custom mounts, deterministically ordered by destination.
	mounts := sortedMounts(p.Mounts)
	for _, m := range mounts {
		switch m.Mode {
		case config.MountTmpfs:
			args = append(args, "--tmpfs", m.Dest)
		case config.MountRW:
			args = append(args, "--bind", m.Src, m.Dest)
		case config.MountDev:
			args = append(args, "--dev-bind", m.Src, m.Dest)
		default: // ro (explicit or default)
			args = append(args, "--ro-bind", m.Src, m.Dest)
		}
	}

	// Secrets: whole-directory bind so atomic updates stay visible
	// (CONCEPT.md §4.7).
	if p.SecretDir != "" {
		args = append(args, "--ro-bind", p.SecretDir, "/run/secrets")
	}

	// Injected resolver configuration.
	if p.ResolvConf != "" {
		args = append(args, "--ro-bind", p.ResolvConf, "/etc/resolv.conf")
	}
	// Generated hosts file: static dns.hosts mappings resolve natively
	// because glibc consults files before DNS.
	if p.HostsFile != "" {
		args = append(args, "--ro-bind", p.HostsFile, "/etc/hosts")
	}

	// Environment hygiene: strip denied host vars first, then apply the
	// explicit set list (set wins, CONCEPT.md §5 env semantics).
	for _, v := range HostDeniedEnvVars {
		args = append(args, "--unsetenv", v)
	}
	for _, v := range p.EnvUnset {
		args = append(args, "--unsetenv", v)
	}
	for _, k := range sortedKeys(p.EnvSet) {
		args = append(args, "--setenv", k, p.EnvSet[k])
	}
	args = append(args,
		"--setenv", "HOME", p.SandboxHome,
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "SHELL", "/bin/bash",
	)
	// PATH mirrors the proven sandbox: repo-local tools first, then the
	// sandbox home, then the system (all absolute so they resolve inside).
	args = append(args, "--setenv", "PATH",
		p.RepoRoot+"/.cache/bin:"+p.SandboxHome+"/.local/bin:/usr/local/bin:/usr/bin:/bin")

	// Guest entrypoint staging: the sandbox has no host paths, so the
	// keg binary is bound into a fresh tmpfs dir and executed there;
	// its argv[1] dispatches to guestMain (see cmd/keg main).
	if p.SelfExe != "" {
		args = append(args,
			"--tmpfs", "/.keg",
			"--ro-bind", p.SelfExe, "/.keg/keg",
		)
	}

	// Raw extra args last: they can add to, not reliably retract, derived
	// arguments (weak ones gated above).
	args = append(args, p.BwrapArgs...)

	args = append(args, "--")
	if p.SelfExe != "" {
		args = append(args, "/.keg/keg", GuestCommandName)
	}
	args = append(args, p.Command...)
	return args, nil
}

func sortedMounts(mounts []config.Mount) []config.Mount {
	out := slices.Clone(mounts)
	slices.SortStableFunc(out, func(a, b config.Mount) int {
		return strings.Compare(a.Dest, b.Dest)
	})
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
