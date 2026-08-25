package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

// buildRunPlan loads and validates all configuration for a sandbox run and
// produces the orchestrator plan. It performs no process management —
// Launch owns that. Errors name the offending file/field.
func buildRunPlan(repoDir, repoCfgPath, userCfgPath string, overlay orchestrator.Overlay, diskName string) (orchestrator.Plan, error) {
	root := repoDir
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	// Repo config: explicit path or <root>/.keg.yaml (required).
	cfgPath := repoCfgPath
	if cfgPath == "" {
		cfgPath = filepath.Join(root, ".keg.yaml")
	}
	repo, err := config.LoadRepo(cfgPath)
	if err != nil {
		return orchestrator.Plan{}, fmt.Errorf("repo %s: %w (create a .keg.yaml or pass --config)", root, err)
	}

	// User config: optional.
	user := &config.User{}
	userPath := userCfgPath
	if userPath == "" {
		userPath = config.DefaultUserPath()
	}
	if data, err := os.ReadFile(userPath); err == nil { // #nosec G304 -- user-controlled config path by design
		parsed, parseErr := config.ParseUser(data)
		if parseErr != nil {
			return orchestrator.Plan{}, fmt.Errorf("%s: %w", userPath, parseErr)
		}
		user = parsed
	} else if userCfgPath != "" {
		// An explicitly requested user config must exist; the default may not.
		return orchestrator.Plan{}, fmt.Errorf("load user config: %w", err)
	}

	effective := config.MatchRepo(user, root)
	vars := config.MergeVars(repo.Vars, effective.Vars, nil)
	_ = vars // consumed by template resolution in WP-M4

	plan := orchestrator.Plan{
		RepoRoot:    root,
		SandboxHome: "/sandbox-home",
		Mounts:      repo.Mounts,
		EnvUnset:    repo.Env.Unset,
		EnvSet:      map[string]string{},
		BwrapArgs:   repo.BwrapArgs,
		AllowWeakBwrap: effective.Security.AllowWeakBwrap != nil &&
			*effective.Security.AllowWeakBwrap,
		Overlay: overlay,
	}
	for k, v := range repo.Env.Set {
		plan.EnvSet[k] = v
	}

	// Prepare host-side directories per overlay mode.
	tmpBase := effective.Paths.TmpBase
	if expanded, err := config.ExpandPath(tmpBase); err == nil && expanded != "" {
		tmpBase = expanded
	} else {
		tmpBase = os.TempDir()
	}
	instanceDir := ""
	if tmpBase != "" {
		// tmpBase originates from the user config; honoring machine-local
		// paths is keg's core function, traversal is not a threat here.
		if err := os.MkdirAll(tmpBase, 0o750); err == nil { // #nosec G703 -- path from trusted local user config

			if d, mkErr := os.MkdirTemp(tmpBase, "keg-"); mkErr == nil {
				instanceDir = d
			}
		}
	}
	if instanceDir == "" {
		d, err2 := os.MkdirTemp("", "keg-")
		if err2 != nil {
			return orchestrator.Plan{}, fmt.Errorf("create instance dir: %w", err2)
		}
		instanceDir = d
	}
	plan.TmpDir = instanceDir

	if overlay == orchestrator.OverlayDisk {
		storageBase := effective.Paths.StorageBase
		if storageBase == "" {
			storageBase = "/var/lib/containers/storage/sandbox"
		}
		if expanded, err := config.ExpandPath(storageBase); err == nil {
			storageBase = expanded
		}
		layer := filepath.Join(storageBase, diskName)
		for _, sub := range []string{"rw", "work"} {
			// layer dir from trusted local user config (storage_base)
			if err := os.MkdirAll(filepath.Join(layer, sub), 0o750); err != nil { // #nosec G703 -- storage_base from trusted local user config

				return orchestrator.Plan{}, fmt.Errorf("prepare disk layer %s: %w", layer, err)
			}
		}
		plan.DiskLayerRW = filepath.Join(layer, "rw")
		plan.DiskLayerWork = filepath.Join(layer, "work")
	}

	return plan, nil
}

// runAction implements `keg run [--] <cmd…>`: build the plan, launch
// bwrap into the reexec guest, forward signals, wait and mirror the exit
// code.
func runAction(ctx context.Context, c *cliCommand) error {
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

	plan, err := buildRunPlan(repoDir, c.String("config"), c.String("user-config"), overlay, diskName)
	if err != nil {
		return err
	}
	plan.Command = c.Args().Slice()
	if len(plan.Command) == 0 {
		plan.Command = []string{"/bin/bash", "-i"}
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

	code, err := sb.Wait()
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}
