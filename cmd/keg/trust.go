package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/smerschjohann/keg/internal/trust"

	"github.com/urfave/cli/v3"
)

func trustCommand() *cli.Command {
	return &cli.Command{
		Name:  "trust",
		Usage: "manage repository configuration trust and approval",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "repo",
				Usage: "repository root (default: current working directory)",
			},
			&cli.BoolFlag{
				Name:  "revoke",
				Usage: "revoke approval for this repository configuration",
			},
			&cli.BoolFlag{
				Name:  "status",
				Usage: "show approval status for this repository configuration (TRUSTED, CHANGED, NONE)",
			},
		},
		Action: trustAction,
	}
}

func trustAction(ctx context.Context, c *cli.Command) error {
	repoDir := c.String("repo")
	if repoDir == "" {
		var err error
		repoDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("determine repo dir: %w", err)
		}
	}

	cfgPath := filepath.Join(repoDir, ".keg.yaml")
	data, err := os.ReadFile(cfgPath) // #nosec G304 -- explicit repo config
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(c.Writer, "No .keg.yaml found in %s\n", repoDir)
			return nil
		}
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}
	if len(data) == 0 {
		_, _ = fmt.Fprintf(c.Writer, ".keg.yaml in %s is empty\n", repoDir)
		return nil
	}

	sha, err := trust.Sha256(data)
	if err != nil {
		return err
	}

	trustPath := trust.Path("")
	store, err := trust.LoadFile(trustPath)
	if err != nil {
		return err
	}

	key := trust.CleanRepoKey(repoDir)

	if c.Bool("status") {
		entry, exists := store.Repos[key]
		if !exists || entry.ApprovedSHA == "" {
			_, _ = fmt.Fprintf(c.Writer, "Status: NONE\nChecksum: %s\n", sha)
			return nil
		}
		if entry.ApprovedSHA == sha {
			_, _ = fmt.Fprintf(c.Writer, "Status: TRUSTED\nChecksum: %s\n", sha)
			return nil
		}
		_, _ = fmt.Fprintf(c.Writer, "Status: CHANGED\nChecksum: %s\n", sha)
		return nil
	}

	if c.Bool("revoke") {
		trust.Revoke(store, repoDir)
		if err := trust.SaveFile(trustPath, store); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(c.Writer, "Revoked trust for %s\n", repoDir)
		return nil
	}

	approvedSHA, err := trust.Approve(store, repoDir, data)
	if err != nil {
		return err
	}
	if err := trust.SaveFile(trustPath, store); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.Writer, "Approved configuration for %s\nChecksum: %s\n", repoDir, approvedSHA)
	return nil
}
