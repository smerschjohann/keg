package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/storage"

	"github.com/urfave/cli/v3"
)

// resolveStorageBase resolves the persistent layer storage directory using the
// precedence: CLI flag > repo-matched user config > global user config > default.
func resolveStorageBase(c *cliCommand) (string, error) {
	if s := c.String("storage-base"); s != "" {
		if exp, err := config.ExpandPath(s); err == nil {
			return exp, nil
		}
		return s, nil
	}

	repoDir := c.String("repo")
	if repoDir == "" {
		if wd, err := os.Getwd(); err == nil {
			repoDir = wd
		}
	}
	if resolved, err := filepath.EvalSymlinks(repoDir); err == nil {
		repoDir = resolved
	}
	if abs, err := filepath.Abs(repoDir); err == nil {
		repoDir = abs
	}

	userPath := c.String("user-config")
	if userPath == "" {
		userPath = config.DefaultUserPath()
	}
	user := &config.User{}
	if data, err := os.ReadFile(userPath); err == nil { // #nosec G304 -- user-controlled path
		if parsed, parseErr := config.ParseUser(data); parseErr == nil {
			user = parsed
		} else {
			return "", fmt.Errorf("%s: %w", userPath, parseErr)
		}
	} else if c.String("user-config") != "" {
		return "", fmt.Errorf("load user config: %w", err)
	}

	effective := config.MatchRepo(user, repoDir)
	storageBase := effective.Paths.StorageBase
	if storageBase == "" {
		storageBase = "/var/lib/containers/storage/sandbox"
	}
	if exp, err := config.ExpandPath(storageBase); err == nil {
		storageBase = exp
	}
	return storageBase, nil
}

func listCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list persistent overlay layers",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "repo",
				Usage: "repository root (default: current working directory)",
			},
			&cli.StringFlag{
				Name:  "storage-base",
				Usage: "override persistent storage base directory",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			storageBase, err := resolveStorageBase(c)
			if err != nil {
				return err
			}
			layers, err := storage.List(storageBase)
			if err != nil {
				return err
			}
			if len(layers) == 0 {
				_, _ = fmt.Fprintf(c.Writer, "No persistent layers found in %s\n", storageBase)
				return nil
			}

			tw := tabwriter.NewWriter(c.Writer, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "TYPE\tNAME\tSIZE\tLAST MODIFIED")
			for _, l := range layers {
				mtimeStr := "-"
				if !l.ModTime.IsZero() {
					mtimeStr = l.ModTime.Format("2006-01-02 15:04:05")
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Type, l.Name, storage.FormatSize(l.SizeBytes), mtimeStr)
			}
			return tw.Flush()
		},
	}
}

func cleanCommand() *cli.Command {
	return &cli.Command{
		Name:  "clean",
		Usage: "delete a persistent overlay layer",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "all",
				Usage: "delete all persistent layers (repo and cache)",
			},
			&cli.StringFlag{
				Name:  "repo",
				Usage: "repository root (default: current working directory)",
			},
			&cli.StringFlag{
				Name:  "storage-base",
				Usage: "override persistent storage base directory",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			storageBase, err := resolveStorageBase(c)
			if err != nil {
				return err
			}
			if c.Bool("all") {
				if err := storage.CleanAll(storageBase); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(c.Writer, "Cleaned all persistent layers in %s\n", storageBase)
				return nil
			}
			name := c.Args().First()
			if name == "" {
				return fmt.Errorf("clean requires a layer NAME or --all")
			}
			if err := storage.CleanRepo(storageBase, name); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.Writer, "Cleaned layer %q\n", name)
			return nil
		},
	}
}

func cleanCacheCommand() *cli.Command {
	return &cli.Command{
		Name:  "clean-cache",
		Usage: "delete persistent cache overlay layers",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "all",
				Usage: "delete all persistent cache layers",
			},
			&cli.StringFlag{
				Name:  "repo",
				Usage: "repository root (default: current working directory)",
			},
			&cli.StringFlag{
				Name:  "storage-base",
				Usage: "override persistent storage base directory",
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			storageBase, err := resolveStorageBase(c)
			if err != nil {
				return err
			}
			name := c.Args().First()
			if name == "" || c.Bool("all") {
				if err := storage.CleanAllCaches(storageBase); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(c.Writer, "Cleaned all cache layers in %s\n", storageBase)
				return nil
			}
			if err := storage.CleanCache(storageBase, name); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.Writer, "Cleaned cache layer %q\n", name)
			return nil
		},
	}
}
