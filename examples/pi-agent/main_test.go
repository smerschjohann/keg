package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPiAgent_SecretRead(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "ai_secret_key")
	expected := "ai-sec-test-12345"

	if err := os.WriteFile(secretFile, []byte(expected), 0o400); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AI_SECRET_KEY", secretFile)

	data, err := os.ReadFile(os.Getenv("AI_SECRET_KEY"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != expected {
		t.Errorf("secret = %q, want %q", string(data), expected)
	}
}
