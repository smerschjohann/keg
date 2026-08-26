// Command keg starts isolated development sandboxes based on bubblewrap
// with zero-trust egress. Architecture: see CONCEPT.md.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/smerschjohann/keg/internal/orchestrator"

	"github.com/urfave/cli/v3"
)

// cliCommand aliases the urfave/cli command type so run.go stays readable.
type cliCommand = cli.Command

// NewCommand builds the keg root command. It is factored out so tests
// can drive the CLI in-process (smoke tests, help-text assertions).
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "keg",
		Usage: "isolated development sandbox with zero-trust egress",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to the repo config (default: <repo>/.keg.yaml)",
			},
			&cli.StringFlag{
				Name:  "user-config",
				Usage: "path to the user config (default: $XDG_CONFIG_HOME/keg/config.yaml)",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "enable verbose logging",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "run",
				Aliases: []string{"r"},
				Usage:   "start a sandbox and run a command inside it (default: interactive shell)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "repo",
						Usage: "repository root (default: current working directory)",
					},
					&cli.BoolFlag{
						Name:  "ephemeral",
						Usage: "discard all repo writes when the sandbox exits (invisible tmpfs overlay)",
					},
					&cli.StringFlag{
						Name:  "disk-overlay",
						Usage: "use a persistent on-disk layer with the given NAME",
					},
					&cli.BoolFlag{
						Name:  "isolate-caches",
						Usage: "discard all cache writes when the sandbox exits (invisible tmpfs overlay over cache mounts)",
					},
					&cli.StringFlag{
						Name:  "isolated-cache-name",
						Usage: "use a persistent on-disk cache layer with the given NAME",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return runAction(ctx, c)
				},
			},
			delegateCommand(),
			listCommand(),
			cleanCommand(),
			cleanCacheCommand(),
			{
				Name:  "serve",
				Usage: "start the remote-control daemon (unix socket/TCP)",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("serve: not implemented yet (WP-M9)")
					return nil
				},
			},
		},
	}
}

func main() {
	// Reentrant entrypoints (classic reexec + bwrap-bound guest routing):
	if orchestrator.InitGuestDispatch() {
		return
	}
	if err := NewCommand().Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
