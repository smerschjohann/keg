// Package orchestrator builds bubblewrap argument lists and manages the
// sandbox lifecycle (socketpairs, reexec, cleanup). The argument builder is
// a pure, total function: no I/O, no global state — fully unit-testable.
package orchestrator

import (
	"fmt"
	"slices"
	"strings"

	"github.com/smerschjohann/keg/internal/config"
)

// FD plan — single source of truth for inherited file descriptors inside
// the sandbox (CONCEPT.md §9).
const (
	FDProxy  = 3 // Kanal A: egress proxy
	FDDNS    = 4 // Kanal B: DNS
	FDRunner = 5 // Kanal C: delegation runner
	// FDPreserved is the number of extra FDs bwrap must preserve (fds
	// 3..2+FDPreserved stay open across exec).
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

	Mounts   []config.Mount    // custom binds, template-resolved
	EnvUnset []string          // additional vars to strip beyond HostDeniedEnvVars
	EnvSet   map[string]string // sandbox environment values

	BwrapArgs      []string // raw extra args, appended after all derived args
	AllowWeakBwrap bool     // security.allow_weak_bwrap from user config

	Overlay       Overlay
	DiskLayerRW   string // host dir with upper layer (OverlayDisk)
	DiskLayerWork string // host dir with work layer (OverlayDisk)

	Command []string // command to exec after `--`
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
		"--die-with-parent",
		"--disable-userns",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)

	// Base system: read-only /usr plus merged-usr symlinks, linker and CA
	// material for CGO builds and TLS.
	args = append(args,
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", "/etc/alternatives", "/etc/alternatives",
		"--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs",
	)

	// Repository write mode.
	switch p.Overlay {
	case OverlayEphemeral:
		args = append(args, "--tmp-overlay", p.RepoRoot)
	case OverlayDisk:
		args = append(args, "--overlay", p.DiskLayerRW+":"+p.DiskLayerWork+":"+p.RepoRoot)
	default:
		args = append(args, "--bind", p.RepoRoot, p.RepoRoot)
	}

	// Sandbox home as writable tmpfs.
	if p.SandboxHome != "" {
		args = append(args, "--tmpfs", p.SandboxHome)
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
	)

	// Raw extra args last: they can add to, not reliably retract, derived
	// arguments (weak ones gated above).
	args = append(args, p.BwrapArgs...)

	args = append(args, "--")
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
