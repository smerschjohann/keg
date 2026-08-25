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

func main() {
	cmd := &cli.Command{
		Name:  "keg",
		Usage: "isolated development sandbox with zero-trust egress",
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
				Name:  "serve",
				Usage: "start the remote-control daemon (unix socket/TCP)",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("serve: not implemented yet (WP-M9)")
					return nil
				},
			},
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
