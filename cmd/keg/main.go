// Command keg starts isolated development sandboxes based on bubblewrap
// with zero-trust egress. Architecture: see CONCEPT.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/smerschjohann/keg/internal/orchestrator"

	"github.com/urfave/cli/v3"
)

// Version is the current release version of keg, set via ldflags at build time.
var Version = "dev"

// cliCommand aliases the urfave/cli command type so run.go stays readable.
type cliCommand = cli.Command

// NewCommand builds the keg root command. It is factored out so tests
// can drive the CLI in-process (smoke tests, help-text assertions).
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:      "keg",
		Usage:     "Kernel-isolated Execution with Gateways — isolated development sandbox with zero-trust egress",
		Version:   Version,
		ErrWriter: os.Stderr,
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
					&cli.StringFlag{
						Name:    "name",
						Aliases: []string{"n"},
						Usage:   "instance name for deterministic instance directories (enables parallel sandboxes)",
					},
					&cli.StringSliceFlag{
						Name:    "env",
						Aliases: []string{"e"},
						Usage:   "pass through (-e VAR) or set (-e VAR=value) environment variable in sandbox (repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "var",
						Aliases: []string{"V"},
						Usage:   "set template variable (KEY=value, repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "publish",
						Aliases: []string{"p", "port"},
						Usage:   "publish a container port to the host (e.g. -p 8080, -p 8080:8080, -p 0.0.0.0:1234:2345, -p :8080) (repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "forward-host",
						Aliases: []string{"L", "forward"},
						Usage:   "forward a host/network service into the container (e.g. -L 2345:127.0.0.1:1234, -L 5432:db.internal:5432) (repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "allow-sni",
						Aliases: []string{"sni"},
						Usage:   "allow additional egress domain/SNI in sandbox (e.g. --allow-sni proxy.golang.org, --allow-sni \"*.example.com\", --allow-sni \"*\") (repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "allow-network",
						Aliases: []string{"allow-net", "allow-cidr"},
						Usage:   "allow egress to specific destination CIDR ranges or IPs (repeatable)",
					},
					&cli.StringSliceFlag{
						Name:    "block-network",
						Aliases: []string{"block-net", "block-cidr"},
						Usage:   "block egress to specific destination CIDR ranges or IPs (repeatable)",
					},
					&cli.BoolFlag{
						Name:  "allow-all-network",
						Usage: "disable all network/CIDR blocks and allow unrestricted destination IPs",
					},
					&cli.BoolFlag{
						Name:  "inherit-all",
						Usage: "pass through all host environment variables (except denied credentials/proxies)",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return runAction(ctx, c)
				},
			},
			delegateCommand(),
			trustCommand(),
			agentCommand(),
			listCommand(),
			cleanCommand(),
			cleanCacheCommand(),
			{
				Name:  "serve",
				Usage: "start the remote-control daemon (unix socket/TCP)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "listen",
						Aliases: []string{"l"},
						Usage:   "listen address: unix:///path/to/sock or host:port",
					},
					&cli.StringFlag{
						Name:  "auth",
						Usage: "authentication mode: token or none",
						Value: "none",
					},
					&cli.StringFlag{
						Name:    "token",
						Usage:   "authentication token (required for network binds)",
						Sources: cli.EnvVars("KEG_AUTH_TOKEN"),
					},
					&cli.IntFlag{
						Name:  "max-sandboxes",
						Usage: "maximum number of concurrent sandboxes",
						Value: 10,
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "enable debug logging",
					},
				},
				Action: serveAction,
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
		fmt.Fprintf(os.Stderr, "keg: %v\n", err)
		var exitErr cli.ExitCoder
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}
