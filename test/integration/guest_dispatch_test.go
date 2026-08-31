//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/trust"
)

// TestPublicAPI_GuestDispatchInTestBinary reproduces the external-consumer
// failure mode: pkg/keg reexecs the calling binary as the sandbox netns
// stage and guest entrypoint. A Go test binary without the dispatch gate
// re-runs its whole test suite inside the sandbox (observed in the wild as
// `go test` output appearing in the guest's stdout). The public API must
// therefore expose the reentry gate, and Launch must work from a test
// binary's TestMain.
func TestPublicAPI_GuestDispatchInTestBinary(t *testing.T) {
	findBwrap(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not found in PATH, skipping: %v", err)
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	modDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte(fmt.Sprintf(`module guestsuite.test/dispatch

go 1.25.0

require github.com/smerschjohann/keg v0.0.0

replace github.com/smerschjohann/keg => %s
`, repoRoot)), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	gosum, err := os.ReadFile(filepath.Join(repoRoot, "go.sum"))
	if err != nil {
		t.Fatalf("read go.sum: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "go.sum"), gosum, 0o644); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}

	// The external module runs its own sandbox: approve its repo config so
	// BuildPlan's trust gate passes without interaction.
	cfgContent := "version: \"1\"\n"
	if err := os.WriteFile(filepath.Join(modDir, ".keg.yaml"), []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write .keg.yaml: %v", err)
	}
	storePath := trust.DefaultTrustPath()
	store, _ := trust.LoadFile(storePath)
	_, _ = trust.Approve(store, modDir, []byte(cfgContent), nil)
	_ = trust.SaveFile(storePath, store)

	suiteDir := filepath.Join(modDir, "dispatch")
	if err := os.MkdirAll(suiteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	suite := `package dispatch

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/pkg/keg"
)

func TestMain(m *testing.M) {
	if keg.InitGuestDispatch() {
		return
	}
	os.Exit(m.Run())
}

func TestLaunchFromTestBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	sb, err := keg.Launch(context.Background(), os.Getenv("KEG_DISPATCH_REPO"),
		keg.WithCommand("/bin/sh", "-c", "printf GUEST_DISPATCH_OK"),
		keg.WithStdout(&stdout),
		keg.WithStderr(&stderr),
	)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	code, waitErr := sb.Wait()
	_ = sb.Close()
	if waitErr != nil || code != 0 {
		t.Fatalf("wait: code=%d err=%v stdout=%q stderr=%q", code, waitErr, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "GUEST_DISPATCH_OK") {
		t.Fatalf("guest output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
`
	if err := os.WriteFile(filepath.Join(suiteDir, "dispatch_test.go"), []byte(suite), 0o644); err != nil {
		t.Fatalf("write dispatch_test.go: %v", err)
	}

	// A short timeout bounds the regression mode: without the dispatch gate
	// the guest re-runs the suite (recursively launching sandboxes) instead
	// of exec'ing the command.
	run := exec.Command("go", "test", "./dispatch", "-run", "TestLaunchFromTestBinary", "-count=1", "-v", "-timeout", "60s")
	run.Dir = modDir
	run.Env = append(os.Environ(),
		"KEG_DISPATCH_REPO="+modDir,
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=mod",
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("external test-binary run failed: %v\n%s", err, out)
	}
	// The marker itself is asserted inside the guest test (its own buffer);
	// here we only need the suite to have passed end-to-end.
	if !strings.Contains(string(out), "--- PASS: TestLaunchFromTestBinary") {
		t.Fatalf("expected TestLaunchFromTestBinary to pass, got:\n%s", out)
	}
}
