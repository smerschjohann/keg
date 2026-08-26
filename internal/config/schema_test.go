package config_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
)

func TestEmbeddedSchemas_ValidJSON(t *testing.T) {
	t.Run("repo schema", func(t *testing.T) {
		data := config.RepoSchemaJSON()
		if len(data) == 0 {
			t.Fatal("RepoSchemaJSON() returned empty data")
		}
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("RepoSchemaJSON() is not valid JSON: %v", err)
		}
		if parsed["title"] != "Keg Repository Configuration" {
			t.Errorf("unexpected title: %v", parsed["title"])
		}
		if parsed["$schema"] == nil {
			t.Error("missing $schema key")
		}
	})

	t.Run("user schema", func(t *testing.T) {
		data := config.UserSchemaJSON()
		if len(data) == 0 {
			t.Fatal("UserSchemaJSON() returned empty data")
		}
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("UserSchemaJSON() is not valid JSON: %v", err)
		}
		if parsed["title"] != "Keg User Configuration" {
			t.Errorf("unexpected title: %v", parsed["title"])
		}
		if parsed["$schema"] == nil {
			t.Error("missing $schema key")
		}
	})
}

func TestEmbeddedSchemas_ParseActualExamples(t *testing.T) {
	// Verify that example files in the repository can be parsed into structs without errors
	examples := []string{
		"../../examples/agy-user-config/user_config.yaml",
		"../../examples/agy-user-sandbox/user_config.yaml",
		"../../examples/pi-agent/user_config.yaml",
	}
	for _, ex := range examples {
		t.Run(ex, func(t *testing.T) {
			data, err := os.ReadFile(ex)
			if err != nil {
				t.Fatalf("read example %s: %v", ex, err)
			}
			u, err := config.ParseUser(data)
			if err != nil {
				t.Fatalf("ParseUser(%s) failed: %v", ex, err)
			}
			if u == nil {
				t.Fatal("parsed user is nil")
			}
		})
	}
}
