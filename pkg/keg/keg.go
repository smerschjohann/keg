// Package keg provides the Go library API for programmatically managing
// isolated keg sandboxes (CONCEPT.md §8).
package keg

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// Sandbox represents a running keg sandbox instance.
type Sandbox struct {
	mu sync.Mutex

	sb       *orchestrator.Sandbox
	plan     orchestrator.Plan
	cancelFn context.CancelFunc
	closed   bool
	cleanups []func()
}

// Option configures sandbox launch parameters.
type Option func(*configOptions)

type configOptions struct {
	repoConfig        string
	userConfig        string
	ephemeral         bool
	diskOverlay       string
	isolateCaches     bool
	isolatedCacheName string
	instanceName      string
	auditFile         string
	stdin             io.Reader
	stdout            io.Writer
	stderr            io.Writer
	command           []string
	allowSNI          []string
	allowNetworks     []string
	blockNetworks     []string
	allowAllNetwork   bool
}

func defaultOptions() *configOptions {
	return &configOptions{
		command: []string{"/bin/bash", "-i"},
	}
}

// InitGuestDispatch must be called at the very beginning of the process
// entry point (main() or TestMain) of every binary that uses Launch:
//
//	func main() {
//		if keg.InitGuestDispatch() {
//			return
//		}
//		// ... normal program flow; keg.Launch(...) is now safe to call.
//	}
//
// Launch reexecs the *calling* binary as the sandbox stages and guest
// entrypoint (netns stage via argv[1], guest via argv[0]/argv[1]). The
// binary must therefore recognize those reentry shapes and delegate to the
// sandbox entrypoint instead of its normal work — otherwise a guest
// re-invocation silently re-executes the caller's regular payload (e.g. a
// test binary re-runs its whole suite inside the sandbox). The gate returns
// true when this process IS a sandbox component; callers then return
// immediately. Host processes (no reentry shape) get false.
func InitGuestDispatch() bool {
	return orchestrator.InitGuestDispatch()
}

// WithRepoConfig sets an explicit path to .keg.yaml.
func WithRepoConfig(path string) Option {
	return func(o *configOptions) { o.repoConfig = path }
}

// WithUserConfig sets an explicit path to the host user config.
func WithUserConfig(path string) Option {
	return func(o *configOptions) { o.userConfig = path }
}

// WithEphemeral enables an ephemeral tmpfs overlay over the repo root.
func WithEphemeral() Option {
	return func(o *configOptions) { o.ephemeral = true }
}

// WithDiskOverlay enables a named persistent disk overlay over the repo root.
func WithDiskOverlay(name string) Option {
	return func(o *configOptions) { o.diskOverlay = name }
}

// WithIsolateCaches enables ephemeral tmpfs cache isolation.
func WithIsolateCaches() Option {
	return func(o *configOptions) { o.isolateCaches = true }
}

// WithIsolatedCacheName enables a named persistent disk overlay for language caches.
func WithIsolatedCacheName(name string) Option {
	return func(o *configOptions) { o.isolatedCacheName = name }
}

// WithName sets a deterministic instance name for parallel sandboxes.
func WithName(name string) Option {
	return func(o *configOptions) { o.instanceName = name }
}

// WithAuditFile directs Allow/Deny audit records to the specified file.
func WithAuditFile(path string) Option {
	return func(o *configOptions) { o.auditFile = path }
}

// WithStdin sets the standard input reader.
func WithStdin(r io.Reader) Option {
	return func(o *configOptions) { o.stdin = r }
}

// WithStdout sets the standard output writer.
func WithStdout(w io.Writer) Option {
	return func(o *configOptions) { o.stdout = w }
}

// WithStderr sets the standard error writer.
func WithStderr(w io.Writer) Option {
	return func(o *configOptions) { o.stderr = w }
}

// WithCommand sets the command to execute inside the sandbox.
func WithCommand(cmd ...string) Option {
	return func(o *configOptions) { o.command = cmd }
}

// WithAllowSNI permits additional egress domains or wildcard patterns ("*").
func WithAllowSNI(domains ...string) Option {
	return func(o *configOptions) { o.allowSNI = append(o.allowSNI, domains...) }
}

// WithAllowNetwork permits specific destination CIDRs or IPs.
func WithAllowNetwork(cidrs ...string) Option {
	return func(o *configOptions) { o.allowNetworks = append(o.allowNetworks, cidrs...) }
}

// WithBlockNetwork blocks specific destination CIDRs or IPs.
func WithBlockNetwork(cidrs ...string) Option {
	return func(o *configOptions) { o.blockNetworks = append(o.blockNetworks, cidrs...) }
}

// WithAllowAllNetwork disables all destination CIDR/IP restrictions.
func WithAllowAllNetwork() Option {
	return func(o *configOptions) { o.allowAllNetwork = true }
}

// SecretPath returns the in-sandbox path for a given secret name.
func (s *Sandbox) SecretPath(name string) string {
	return "/run/secrets/" + name
}

// Pid returns the process ID of the sandbox process on the host.
func (s *Sandbox) Pid() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sb == nil {
		return 0
	}
	return s.sb.Pid()
}

// Signal forwards a signal to the sandbox.
func (s *Sandbox) Signal(sig os.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sb == nil {
		return nil
	}
	return s.sb.Signal(sig)
}

// Wait blocks until the sandbox process exits and returns its exit code.
func (s *Sandbox) Wait() (int, error) {
	if s.sb == nil {
		return 1, fmt.Errorf("sandbox is not running")
	}
	return s.sb.Wait()
}

// Close terminates the sandbox and cleans up all associated resources.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.cancelFn != nil {
		s.cancelFn()
	}
	if s.sb != nil {
		s.sb.Close()
	}
	for _, cleanup := range s.cleanups {
		cleanup()
	}
	s.cleanups = nil
	return nil
}

// Launch boots an isolated sandbox rooted at repoRoot according to .keg.yaml
// and the specified options (CONCEPT.md §8).
func Launch(ctx context.Context, repoRoot string, opts ...Option) (*Sandbox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.ephemeral && cfg.diskOverlay != "" {
		return nil, fmt.Errorf("--ephemeral and --disk-overlay are mutually exclusive")
	}
	if cfg.isolateCaches && cfg.isolatedCacheName != "" {
		return nil, fmt.Errorf("--isolate-caches and --isolated-cache-name are mutually exclusive")
	}

	overlay := orchestrator.OverlayPlain
	if cfg.ephemeral {
		overlay = orchestrator.OverlayEphemeral
	} else if cfg.diskOverlay != "" {
		overlay = orchestrator.OverlayDisk
	}

	cacheOverlay := orchestrator.OverlayPlain
	if cfg.isolateCaches {
		cacheOverlay = orchestrator.OverlayEphemeral
	} else if cfg.isolatedCacheName != "" {
		cacheOverlay = orchestrator.OverlayDisk
	}

	plan, userCfg, err := orchestrator.BuildPlan(repoRoot, cfg.repoConfig, cfg.userConfig, overlay, cfg.diskOverlay, cacheOverlay, cfg.isolatedCacheName, cfg.instanceName)
	if err != nil {
		return nil, err
	}

	if cfg.allowAllNetwork {
		plan.AllowAllNetwork = true
	}
	if len(cfg.allowNetworks) > 0 || len(cfg.blockNetworks) > 0 {
		if err := orchestrator.AddNetworkCIDRsToPlan(&plan, cfg.allowNetworks, cfg.blockNetworks); err != nil {
			return nil, err
		}
	}
	if len(cfg.allowSNI) > 0 {
		if err := orchestrator.AddSNIDomainsToPlan(&plan, cfg.allowSNI); err != nil {
			return nil, err
		}
	}

	if cfg.auditFile != "" {
		plan.AuditFile = cfg.auditFile
	}
	if cfg.stdin != nil {
		plan.Stdin = cfg.stdin
	}
	if cfg.stdout != nil {
		plan.Stdout = cfg.stdout
	}
	if cfg.stderr != nil {
		plan.Stderr = cfg.stderr
	}
	if len(cfg.command) > 0 {
		plan.Command = cfg.command
	}

	launchCtx, cancelFn := context.WithCancel(ctx)

	var cleanups []func()
	cleanups = append(cleanups, func() {
		if plan.TmpDir != "" && plan.InstanceName == "" {
			_ = os.RemoveAll(plan.TmpDir)
		}
	})

	var auditFileWriter io.Writer
	if plan.AuditFile != "" {
		if err := os.MkdirAll(filepath.Dir(plan.AuditFile), 0o750); err == nil {
			af, err := os.OpenFile(plan.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- trusted path
			if err != nil {
				cancelFn()
				return nil, fmt.Errorf("open audit file %s: %w", plan.AuditFile, err)
			}
			cleanups = append(cleanups, func() { _ = af.Close() })
			auditFileWriter = af
			plan.AuditWriter = af
		}
	}

	inst := plan.InstanceName
	if inst == "" {
		inst = filepath.Base(plan.RepoRoot)
	}
	auditLogger := orchestrator.NewAuditLogger(auditFileWriter, nil, inst)
	plan.AuditWriter = auditLogger

	sb, err := orchestrator.Launch(launchCtx, plan)
	if err != nil {
		cancelFn()
		for _, c := range cleanups {
			c()
		}
		return nil, err
	}

	result := &Sandbox{
		sb:       sb,
		plan:     plan,
		cancelFn: cancelFn,
		cleanups: cleanups,
	}

	if err := orchestrator.StartBackgroundServices(launchCtx, sb, plan, userCfg, auditLogger); err != nil {
		_ = result.Close()
		return nil, err
	}

	return result, nil
}
