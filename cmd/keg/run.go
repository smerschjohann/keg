package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// buildRunPlan loads and validates all configuration for a sandbox run and
// produces the orchestrator plan. It delegates to orchestrator.BuildPlan.
func buildRunPlan(repoDir, repoCfgPath, userCfgPath string, overlay orchestrator.Overlay, diskName string, cacheOverlay orchestrator.Overlay, isolatedCacheName, instanceName string) (orchestrator.Plan, error) {
	plan, _, err := orchestrator.BuildPlan(repoDir, repoCfgPath, userCfgPath, overlay, diskName, cacheOverlay, isolatedCacheName, instanceName)
	return plan, err
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

	plan, userCfg, err := orchestrator.BuildPlan(repoDir, c.String("config"), c.String("user-config"), overlay, diskName, cacheOverlay, isolatedCacheName, instanceName)
	if err != nil {
		return err
	}
	plan.Command = c.Args().Slice()
	if len(plan.Command) == 0 {
		plan.Command = []string{"/bin/bash", "-i"}
	}

	var auditWriter io.Writer
	if plan.AuditFile != "" {
		af, err := os.OpenFile(plan.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- trusted user config
		if err != nil {
			return fmt.Errorf("open audit file %s: %w", plan.AuditFile, err)
		}
		defer func() { _ = af.Close() }()
		auditWriter = af
	}

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

	if err := orchestrator.StartBackgroundServices(ctx, sb, plan, userCfg, auditWriter); err != nil {
		fmt.Fprintf(os.Stderr, "keg: services: %v\n", err)
	}

	code, err := sb.Wait()
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}
