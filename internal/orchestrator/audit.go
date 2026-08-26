package orchestrator

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditLogger formats and writes audit events:
// - To fileWriter: formatted with RFC3339 timestamp and sandbox instance name.
// - To verboseWriter (if non-nil): plain decision line for terminal output.
type AuditLogger struct {
	fileWriter    io.Writer
	verboseWriter io.Writer
	instance      string
	mu            sync.Mutex
}

// NewAuditLogger creates a thread-safe AuditLogger.
func NewAuditLogger(fileWriter, verboseWriter io.Writer, instance string) *AuditLogger {
	return &AuditLogger{
		fileWriter:    fileWriter,
		verboseWriter: verboseWriter,
		instance:      instance,
	}
}

// Write implements io.Writer, processing line-based audit events.
func (a *AuditLogger) Write(p []byte) (n int, err error) {
	if a == nil {
		return len(p), nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	lines := strings.Split(strings.TrimRight(string(p), "\n"), "\n")
	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range lines {
		if line == "" {
			continue
		}
		if a.fileWriter != nil {
			formatted := fmt.Sprintf("%s [%s] %s\n", now, a.instance, line)
			_, _ = a.fileWriter.Write([]byte(formatted))
		}
		if a.verboseWriter != nil {
			_, _ = a.verboseWriter.Write([]byte(line + "\n"))
		}
	}
	return len(p), nil
}

// DefaultAuditPath returns the default audit log location:
// $XDG_CONFIG_HOME/keg/audit.log or ~/.config/keg/audit.log.
func DefaultAuditPath() string {
	if configHome := os.Getenv("XDG_CONFIG_HOME"); configHome != "" {
		return filepath.Join(configHome, "keg", "audit.log")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "keg", "audit.log")
	}
	return ""
}
