package main

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/smerschjohann/keg/internal/config"

	"github.com/urfave/cli/v3"
)

const sandboxJustTemplate = `# sandbox.just — Delegation pattern for running host-only tasks from inside keg

in_sandbox := env_var_or_default("KEG_RUNNER", env_var_or_default("KEG_DELEGATION", env_var_or_default("CODE_SANDBOX", "0")))

set positional-arguments := true

# Delegate a task to the host runner
[private]
delegate *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{in_sandbox}}" != "1" ]; then
        echo "✗ 'just delegate' can only be executed inside an active sandbox." >&2
        exit 1
    fi
    exec keg delegate "$@"
`

//go:embed agent_prompt.md
var agentPromptText string

func agentCommand() *cli.Command {
	return &cli.Command{
		Name:  "agent",
		Usage: "agent helpers for repository setup, prompts, and schema inspection",
		Commands: []*cli.Command{
			{
				Name:  "prompt",
				Usage: "print instructions and best practices for AI agents configuring repositories with keg",
				Action: func(ctx context.Context, c *cli.Command) error {
					_, _ = fmt.Fprintln(c.Writer, agentPromptText)
					return nil
				},
			},
			{
				Name:      "schema",
				Usage:     "dump JSON schema for configuration files (repo | user)",
				ArgsUsage: "[repo | user]",
				Action: func(ctx context.Context, c *cli.Command) error {
					schemaType := c.Args().First()
					if schemaType == "" {
						schemaType = "repo"
					}
					switch strings.ToLower(schemaType) {
					case "repo", ".keg.yaml", "keg":
						_, _ = c.Writer.Write(config.RepoSchemaJSON())
						_, _ = fmt.Fprintln(c.Writer)
						return nil
					case "user", "config.yaml", "config":
						_, _ = c.Writer.Write(config.UserSchemaJSON())
						_, _ = fmt.Fprintln(c.Writer)
						return nil
					default:
						return fmt.Errorf("invalid schema type %q: must be 'repo' or 'user'", schemaType)
					}
				},
			},
			{
				Name:  "sandbox-just",
				Usage: "print canonical sandbox.just snippet for justfile delegation",
				Action: func(ctx context.Context, c *cli.Command) error {
					_, _ = fmt.Fprint(c.Writer, sandboxJustTemplate)
					return nil
				},
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			_, _ = fmt.Fprintln(c.Writer, agentPromptText)
			return nil
		},
	}
}
