//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/trust"

	"github.com/smerschjohann/keg/pkg/keg"
)

func TestIntegration_GoLibraryAPI(t *testing.T) {
	if _, err := os.Stat("/usr/bin/bwrap"); err != nil {
		t.Skip("bwrap not found in /usr/bin/bwrap; skipping integration test")
	}

	repoDir := t.TempDir()
	configFile := filepath.Join(repoDir, ".keg.yaml")
	if err := os.WriteFile(configFile, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	storePath := trust.DefaultTrustPath()
	store, _ := trust.LoadFile(storePath)
	_, _ = trust.Approve(store, repoDir, []byte("version: \"1\"\n"), nil)
	_ = trust.SaveFile(storePath, store)

	var stdoutBuf, stderrBuf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sb, err := keg.Launch(ctx, repoDir,
		keg.WithEphemeral(),
		keg.WithStdout(&stdoutBuf),
		keg.WithStderr(&stderrBuf),
		keg.WithCommand("/bin/sh", "-c", "echo hello-library; echo err-library >&2"),
	)
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer sb.Close()

	if sb.Pid() <= 0 {
		t.Errorf("Pid() = %d, want > 0", sb.Pid())
	}

	if path := sb.SecretPath("api_key"); path != "/run/secrets/api_key" {
		t.Errorf("SecretPath = %q, want /run/secrets/api_key", path)
	}

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdoutBuf.String(), "hello-library") {
		t.Errorf("stdout = %q, want 'hello-library'", stdoutBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "err-library") {
		t.Errorf("stderr = %q, want 'err-library'", stderrBuf.String())
	}
}
