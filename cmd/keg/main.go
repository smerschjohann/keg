// Command keg starts isolated development sandboxes based on bubblewrap
// with zero-trust egress. Architecture: see CONCEPT.md.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"
)

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
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("run: not implemented yet (WP-M1, IMPLEMENTATION_PLAN.md §3)")
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list persistent overlay layers",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("list: not implemented yet (WP-M6)")
					return nil
				},
			},
			{
				Name:  "clean",
				Usage: "delete a persistent overlay layer",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("clean: not implemented yet (WP-M6)")
					return nil
				},
			},
			{
				Name:  "clean-cache",
				Usage: "delete persistent cache overlay layers",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("clean-cache: not implemented yet (WP-M6)")
					return nil
				},
			},
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
	if err := NewCommand().Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
