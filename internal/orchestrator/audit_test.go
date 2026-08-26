package orchestrator

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLogger_WritesTimestampAndInstanceToFile(t *testing.T) {
	var fileBuf bytes.Buffer
	var verboseBuf bytes.Buffer

	logger := NewAuditLogger(&fileBuf, &verboseBuf, "test-instance")
	msg := "ERLAUBT api.google.com:443"
	if _, err := logger.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	fileOut := fileBuf.String()
	if !strings.Contains(fileOut, "[test-instance] ERLAUBT api.google.com:443") {
		t.Errorf("file output = %q, want instance prefix and msg", fileOut)
	}
	if !strings.Contains(fileOut, "T") || !strings.Contains(fileOut, "Z") {
		t.Errorf("file output = %q, want RFC3339 timestamp", fileOut)
	}

	verboseOut := verboseBuf.String()
	if verboseOut != "ERLAUBT api.google.com:443\n" {
		t.Errorf("verbose output = %q, want plain message", verboseOut)
	}
}

func TestAuditLogger_NoVerboseWhenNil(t *testing.T) {
	var fileBuf bytes.Buffer
	logger := NewAuditLogger(&fileBuf, nil, "quiet-instance")

	msg := "DNS ERLAUBT googleapis.com"
	if _, err := logger.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	fileOut := fileBuf.String()
	if !strings.Contains(fileOut, "[quiet-instance] DNS ERLAUBT googleapis.com") {
		t.Errorf("file output = %q, want instance prefix and msg", fileOut)
	}
}

func TestDefaultAuditPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/config")
	got := DefaultAuditPath()
	want := filepath.Join("/custom/config", "keg", "audit.log")
	if got != want {
		t.Errorf("DefaultAuditPath = %q, want %q", got, want)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/testuser")
	gotHome := DefaultAuditPath()
	wantHome := filepath.Join("/home/testuser", ".config", "keg", "audit.log")
	if gotHome != wantHome {
		t.Errorf("DefaultAuditPath with HOME = %q, want %q", gotHome, wantHome)
	}
}
