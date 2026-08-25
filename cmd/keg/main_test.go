package main

import (
	"context"
	"strings"
	"testing"
)

// runCLI executes the root command with the given arguments, mirroring an
// actual CLI invocation without spawning a process.
func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	return NewCommand().Run(context.Background(), append([]string{"keg"}, args...))
}

func TestCLI_CommandsExist(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "run", command: "run"},
		{name: "run alias r", command: "r"},
		{name: "list", command: "list"},
		{name: "clean", command: "clean"},
		{name: "clean-cache", command: "clean-cache"},
		{name: "serve", command: "serve"},
	}
	cmd := NewCommand()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range cmd.Commands {
				if c.HasName(tt.command) {
					return
				}
			}
			t.Fatalf("command %q not found", tt.command)
		})
	}
}

func TestCLI_GlobalFlagsDeclared(t *testing.T) {
	tests := []struct {
		name string
		flag string
	}{
		{name: "config", flag: "config"},
		{name: "user-config", flag: "user-config"},
		{name: "verbose", flag: "verbose"},
	}
	cmd := NewCommand()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range cmd.Flags {
				if f.Names()[0] == tt.flag {
					return
				}
			}
			t.Fatalf("global flag --%s not declared", tt.flag)
		})
	}
}

func TestCLI_HelpListsSubcommandsWithUsage(t *testing.T) {
	cmd := NewCommand()
	var out strings.Builder
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "--help"}); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	help := out.String()
	for _, want := range []string{
		"isolated development sandbox",
		"start a sandbox and run a command inside it",
		"list persistent overlay layers",
		"delete a persistent overlay layer",
		"remote-control daemon",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help output missing %q", want)
		}
	}
}

func TestCLI_StubCommandsRun(t *testing.T) {
	// Until the work packages land, every subcommand must at least execute
	// without error so the binary stays usable end-to-end.
	for _, args := range [][]string{{"list"}, {"clean"}, {"clean-cache"}} {
		if err := runCLI(t, args...); err != nil {
			t.Errorf("keg %v: unexpected error: %v", args, err)
		}
	}
}

func TestCLI_RunRejectsMissingCommandSeparator(t *testing.T) {
	// `keg run` without `-- <cmd>` is valid only in interactive mode;
	// both must parse today (stub), real behavior lands with WP-M1.
	if err := runCLI(t, "run"); err != nil {
		t.Fatalf("bare run should be accepted by the stub: %v", err)
	}
}
