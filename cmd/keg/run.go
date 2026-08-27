package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

// buildRunPlan loads and validates all configuration for a sandbox run and
// produces the orchestrator plan. It delegates to orchestrator.BuildPlan.
func buildRunPlan(repoDir, repoCfgPath, userCfgPath string, overlay orchestrator.Overlay, diskName string, cacheOverlay orchestrator.Overlay, isolatedCacheName, instanceName string) (orchestrator.Plan, error) {
	plan, _, err := orchestrator.BuildPlan(repoDir, repoCfgPath, userCfgPath, overlay, diskName, cacheOverlay, isolatedCacheName, instanceName)
	return plan, err
}

func parseEnvFlag(entries []string) (map[string]string, []string, error) {
	set := make(map[string]string)
	var inherit []string

	for _, entry := range entries {
		if entry == "" {
			return nil, nil, fmt.Errorf("empty environment flag entry")
		}
		if strings.HasPrefix(entry, "=") {
			return nil, nil, fmt.Errorf("invalid environment flag entry %q: empty name", entry)
		}
		if k, v, found := strings.Cut(entry, "="); found {
			set[k] = v
			inherit = slices.DeleteFunc(inherit, func(s string) bool { return s == k })
		} else {
			if slices.Contains(orchestrator.HostDeniedEnvVars, entry) {
				// Explicit CLI request to forward a denied host variable:
				// resolve its value from the host environment into set.
				if val, ok := os.LookupEnv(entry); ok {
					set[entry] = val
				}
				inherit = slices.DeleteFunc(inherit, func(s string) bool { return s == entry })
			} else {
				delete(set, entry)
				if !slices.Contains(inherit, entry) {
					inherit = append(inherit, entry)
				}
			}
		}
	}
	return set, inherit, nil
}

func parseVarFlags(entries []string) (map[string]string, error) {
	out := make(map[string]string)
	for _, entry := range entries {
		if entry == "" {
			return nil, fmt.Errorf("empty variable flag entry")
		}
		k, v, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("invalid variable flag entry %q: want KEY=value", entry)
		}
		if k == "" {
			return nil, fmt.Errorf("invalid variable flag entry %q: empty variable name", entry)
		}
		out[k] = v
	}
	return out, nil
}

func parsePublishFlags(entries []string) ([]config.PortSpec, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	specs := make([]config.PortSpec, 0, len(entries))
	for _, entry := range entries {
		spec, err := config.ParsePublishFlag(entry)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

var (
	upstreamProxyFromEnv = orchestrator.UpstreamProxyFromEnv
	firstHostNameserver  = orchestrator.FirstHostNameserver
)

// runAction implements `keg run [--] <cmd…>`: build the plan, launch
// bwrap into the reexec guest, forward signals, wait and mirror the exit
// code.
func runAction(ctx context.Context, c *cliCommand) error {
	if c.Bool("verbose") {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	}

	repoDir := c.String("repo")
	if repoDir == "" {
		var err error
		repoDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("determine repo dir: %w", err)
		}
	}

	overlay := orchestrator.OverlayPlain
	diskName := c.String("disk-overlay")
	switch {
	case c.Bool("ephemeral") && diskName != "":
		return fmt.Errorf("--ephemeral and --disk-overlay are mutually exclusive")
	case c.Bool("ephemeral"):
		overlay = orchestrator.OverlayEphemeral
	case diskName != "":
		overlay = orchestrator.OverlayDisk
	}

	cacheOverlay := orchestrator.OverlayPlain
	isolatedCacheName := c.String("isolated-cache-name")
	switch {
	case c.Bool("isolate-caches") && isolatedCacheName != "":
		return fmt.Errorf("--isolate-caches and --isolated-cache-name are mutually exclusive")
	case c.Bool("isolate-caches"):
		cacheOverlay = orchestrator.OverlayEphemeral
	case isolatedCacheName != "":
		cacheOverlay = orchestrator.OverlayDisk
	}

	instanceName := c.String("name")

	cliSet, cliInherit, err := parseEnvFlag(c.StringSlice("env"))
	if err != nil {
		return err
	}

	cliVars, err := parseVarFlags(c.StringSlice("var"))
	if err != nil {
		return err
	}

	cliPorts, err := parsePublishFlags(c.StringSlice("publish"))
	if err != nil {
		return err
	}

	plan, userCfg, err := orchestrator.BuildPlan(repoDir, c.String("config"), c.String("user-config"), overlay, diskName, cacheOverlay, isolatedCacheName, instanceName, cliVars)
	if err != nil {
		return err
	}

	for k, v := range cliSet {
		plan.EnvSet[k] = v
	}
	plan.EnvInherit = config.UnionStrings(plan.EnvInherit, cliInherit)
	if c.Bool("inherit-all") {
		plan.EnvInheritAll = true
	}

	if len(cliPorts) > 0 {
		if err := orchestrator.AddPortsToPlan(&plan, cliPorts); err != nil {
			return err
		}
	}

	plan.Command = c.Args().Slice()
	if len(plan.Command) == 0 {
		plan.Command = []string{"/bin/bash", "-i"}
	}

	var auditFileWriter io.Writer
	if plan.AuditFile != "" {
		if err := os.MkdirAll(filepath.Dir(plan.AuditFile), 0o750); err == nil {
			af, err := os.OpenFile(plan.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- trusted user config
			if err == nil {
				defer func() { _ = af.Close() }()
				auditFileWriter = af
			}
		}
	}

	var verboseWriter io.Writer
	if c.Bool("verbose") {
		verboseWriter = os.Stderr
	}

	inst := plan.InstanceName
	if inst == "" {
		inst = filepath.Base(plan.RepoRoot)
	}
	auditLogger := orchestrator.NewAuditLogger(auditFileWriter, verboseWriter, inst)

	sb, err := orchestrator.Launch(ctx, plan)
	if err != nil {
		return err
	}
	defer sb.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = sb.Signal(sig)
		}
	}()

	if err := orchestrator.StartBackgroundServices(ctx, sb, plan, userCfg, auditLogger); err != nil {
		fmt.Fprintf(os.Stderr, "keg: services: %v\n", err)
	}

	code, err := sb.Wait()
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}
