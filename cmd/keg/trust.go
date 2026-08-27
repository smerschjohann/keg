package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/smerschjohann/keg/internal/config"
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

	repoCfg, _ := config.ParseRepo(data)
	anchors, _ := config.EffectiveTrustAnchors(repoCfg, repoDir)

	anchorContents := make(map[string][]byte)
	anchorSHAs := make(map[string]string)
	for _, relPath := range anchors {
		p := filepath.Join(repoDir, relPath)
		aBytes, aErr := os.ReadFile(p) // #nosec G304,G703 -- anchor file resolution
		if aErr != nil {
			if errors.Is(aErr, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("read trust anchor %s: %w", p, aErr)
		}
		if len(aBytes) > 0 {
			aSHA, shaErr := trust.Sha256(aBytes)
			if shaErr != nil {
				return shaErr
			}
			anchorContents[relPath] = aBytes
			anchorSHAs[relPath] = aSHA
		}
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
			_, _ = fmt.Fprintf(c.Writer, "Status: NONE\nChecksum (.keg.yaml): %s\n", sha)
			for _, relPath := range anchors {
				if aSHA, ok := anchorSHAs[relPath]; ok {
					_, _ = fmt.Fprintf(c.Writer, "Checksum (%s): %s\n", relPath, aSHA)
				}
			}
			return nil
		}
		if trust.IsTrusted(entry, sha, anchorSHAs) {
			_, _ = fmt.Fprintf(c.Writer, "Status: TRUSTED\nChecksum (.keg.yaml): %s\n", sha)
			for _, relPath := range anchors {
				if aSHA, ok := anchorSHAs[relPath]; ok {
					_, _ = fmt.Fprintf(c.Writer, "Checksum (%s): %s\n", relPath, aSHA)
				}
			}
			return nil
		}
		_, _ = fmt.Fprintf(c.Writer, "Status: CHANGED\nChecksum (.keg.yaml): %s\n", sha)
		for _, relPath := range anchors {
			if aSHA, ok := anchorSHAs[relPath]; ok {
				_, _ = fmt.Fprintf(c.Writer, "Checksum (%s): %s\n", relPath, aSHA)
			}
		}
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

	approvedSHA, err := trust.Approve(store, repoDir, data, anchorContents)
	if err != nil {
		return err
	}
	if err := trust.SaveFile(trustPath, store); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.Writer, "Approved configuration for %s\nChecksum (.keg.yaml): %s\n", repoDir, approvedSHA)
	for _, relPath := range anchors {
		if aSHA, ok := anchorSHAs[relPath]; ok {
			_, _ = fmt.Fprintf(c.Writer, "Checksum (%s): %s\n", relPath, aSHA)
		}
	}
	return nil
}
