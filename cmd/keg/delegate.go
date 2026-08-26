package main

import (
	"context"
	"fmt"
	"os"

	"github.com/smerschjohann/keg/internal/runner"

	"github.com/urfave/cli/v3"
)

// delegateAction runs one job on the host via delegation channel C and
// returns the process exit code for the sandbox shell: the job's own code,
// 126 when the whitelist declines, 125 on protocol errors, 127 when no
// runner is reachable (CONCEPT.md §4.5, AGENTS.md §5).
func delegateAction(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: keg delegate <task|cmd> [args…]")
		return 2
	}
	conn, err := runner.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keg delegate: %v\n", err)
		return runner.CodeNoRunner
	}
	return runner.Exec(conn, argv, "", os.Stdout, os.Stderr)
}

// delegateCommand wires the subcommand. os.Exit here is intentional: the
// exit code IS the contract with `just delegate` recipes.
func delegateCommand() *cli.Command {
	return &cli.Command{
		Name:            "delegate",
		Usage:           "run a whitelisted task on the HOST outside the sandbox (126 = declined)",
		SkipFlagParsing: true,
		Description: "Runs inside the sandbox only. Example Justfile recipe:\n" +
			"  if [ \"{{in_sandbox}}\" = \"1\" ]; then just delegate container-build; fi",
		Action: func(_ context.Context, c *cli.Command) error {
			os.Exit(delegateAction(c.Args().Slice()))
			return nil
		},
	}
}
