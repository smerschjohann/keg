package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLI_AgentCommand_Exists(t *testing.T) {
	cmd := NewCommand()
	for _, c := range cmd.Commands {
		if c.HasName("agent") {
			return
		}
	}
	t.Fatal("command 'agent' not found in root command")
}

func TestCLI_AgentPrompt(t *testing.T) {
	t.Run("agent prompt subcommand", func(t *testing.T) {
		cmd := NewCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		if err := cmd.Run(context.Background(), []string{"keg", "agent", "prompt"}); err != nil {
			t.Fatalf("keg agent prompt failed: %v", err)
		}
		output := out.String()
		for _, want := range []string{
			".keg.yaml",
			"sandbox.just",
			"just delegate",
			"delegated_tasks",
			"import 'sandbox.just'",
		} {
			if !strings.Contains(output, want) {
				t.Errorf("agent prompt missing expected text %q", want)
			}
		}
	})

	t.Run("agent default action outputs prompt", func(t *testing.T) {
		cmd := NewCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		if err := cmd.Run(context.Background(), []string{"keg", "agent"}); err != nil {
			t.Fatalf("keg agent failed: %v", err)
		}
		if !strings.Contains(out.String(), "sandbox.just") {
			t.Errorf("agent default missing expected prompt content")
		}
	})
}

func TestCLI_AgentSchema(t *testing.T) {
	t.Run("schema repo", func(t *testing.T) {
		cmd := NewCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		if err := cmd.Run(context.Background(), []string{"keg", "agent", "schema", "repo"}); err != nil {
			t.Fatalf("keg agent schema repo failed: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed["title"] != "Keg Repository Configuration" {
			t.Errorf("unexpected title: %v", parsed["title"])
		}
	})

	t.Run("schema user", func(t *testing.T) {
		cmd := NewCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		if err := cmd.Run(context.Background(), []string{"keg", "agent", "schema", "user"}); err != nil {
			t.Fatalf("keg agent schema user failed: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed["title"] != "Keg User Configuration" {
			t.Errorf("unexpected title: %v", parsed["title"])
		}
	})

	t.Run("schema invalid type", func(t *testing.T) {
		cmd := NewCommand()
		var out bytes.Buffer
		cmd.Writer = &out
		err := cmd.Run(context.Background(), []string{"keg", "agent", "schema", "invalid"})
		if err == nil {
			t.Fatal("expected error for invalid schema type, got nil")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestCLI_AgentSandboxJust(t *testing.T) {
	cmd := NewCommand()
	var out bytes.Buffer
	cmd.Writer = &out
	if err := cmd.Run(context.Background(), []string{"keg", "agent", "sandbox-just"}); err != nil {
		t.Fatalf("keg agent sandbox-just failed: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"in_sandbox :=",
		"delegate *args:",
		"exec keg delegate \"$@\"",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("sandbox-just template missing %q", want)
		}
	}
}
