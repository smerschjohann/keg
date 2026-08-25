//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// TestSandboxShellIsolated is the WP-M1 DoD test: a shell inside the
// sandbox sees only loopback networking, a tmpfs HOME and a read-only /usr.
func TestSandboxShellIsolated(t *testing.T) {
	dir := t.TempDir()

	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `
echo "IFACES:$(ip -o link show 2>/dev/null | wc -l)"
echo "HOME:$HOME"
if touch "$HOME/probe" 2>/dev/null; then echo "HOME_WRITABLE:yes"; else echo "HOME_WRITABLE:no"; fi
if touch /usr/bin/keg-probe 2>/dev/null; then echo "USR_WRITABLE:yes"; else echo "USR_WRITABLE:no"; fi
echo "REPO_WRITE:$(touch .probe 2>/dev/null && echo yes || echo no)"
echo "MARKER:$SANDBOX_MARKER"
`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}

	checks := map[string]func(string) error{
		"IFACES": func(v string) error {
			// --unshare-all => only loopback exists.
			if v != "1" {
				t.Errorf("expected exactly the loopback interface, got %q interfaces\noutput:\n%s", v, out)
			}
			return nil
		},
		"HOME": func(v string) error {
			if v != "/home/sandbox" {
				t.Errorf("HOME = %q, want /home/sandbox", v)
			}
			return nil
		},
		"HOME_WRITABLE": func(v string) error {
			if v != "yes" {
				t.Errorf("tmpfs home must be writable")
			}
			return nil
		},
		"USR_WRITABLE": func(v string) error {
			if v != "no" {
				t.Errorf("/usr must be read-only inside the sandbox")
			}
			return nil
		},
		"REPO_WRITE": func(v string) error {
			if v != "yes" {
				t.Errorf("repo must be writable inside the sandbox")
			}
			return nil
		},
		"MARKER": func(v string) error {
			if v != "inside" {
				t.Errorf("env.set not applied: MARKER=%q", v)
			}
			return nil
		},
	}
	for key, check := range checks {
		line := strings.Split(out, key+":")
		if len(line) < 2 {
			t.Errorf("output missing %q:\n%s", key, out)
			continue
		}
		value := strings.TrimSpace(strings.SplitN(line[1], "\n", 2)[0])
		if err := check(value); err != nil {
			t.Error(err)
		}
	}
}

// TestSandboxFDInheritance verifies the planned channel FDs arrive inside
// the sandbox as socketpair ends at fds 3/4/5 (CONCEPT.md §9). Other fds
// beyond 0-2 may exist when the *host process* leaks descriptors — that is
// exactly what the FD-leak audit (THREAT_MODEL §5.1, WP-M8) guards against;
// this test only asserts our contract.
func TestSandboxFDInheritance(t *testing.T) {
	dir := t.TempDir()
	script := `for f in 0 1 2 3 4 5; do printf "%s=%s\n" $f "$(readlink /proc/self/fd/$f)"; done`
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, script)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	for _, fd := range []string{"0", "1", "2"} {
		if !strings.Contains(out, fd+"=") {
			t.Errorf("std fd %s missing:\n%s", fd, out)
		}
	}
	for _, fd := range []string{"3", "4", "5"} {
		line := strings.Split(out, fd+"=")
		if len(line) < 2 {
			t.Errorf("channel fd %s missing:\n%s", fd, out)
			continue
		}
		target := strings.TrimSpace(strings.SplitN(line[1], "\n", 2)[0])
		if !strings.HasPrefix(target, "socket:[") {
			t.Errorf("fd %s = %q, want a socket (socketpair end)\n%s", fd, target, out)
		}
	}
}

// TestSandboxEphemeralOverlay proves `--ephemeral` leaves the repository
// untouched on the host after writes inside the sandbox.
func TestSandboxEphemeralOverlay(t *testing.T) {
	dir := t.TempDir()
	out, code := runInSandbox(t, dir, orchestrator.OverlayEphemeral,
		`echo ephemeral-change > from-sandbox.txt && cat from-sandbox.txt`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(dir + "/from-sandbox.txt"); !os.IsNotExist(err) {
		t.Errorf("ephemeral write leaked to host repo: %v", err)
	}
}

// TestSandboxDiskOverlay proves a persistent layer survives sandbox
// exits: run 1 writes into the overlay, run 2 (fresh sandbox, same layer)
// reads it back — while the host repo stays clean. Upper dirs live on the
// ext4 container-disk storage base; the read-only root bind makes
// unprivileged overlayfs persist writes (same principle as dist/jail:
// host root as read-only lower layer).
func TestSandboxDiskOverlay(t *testing.T) {
	storageBase := "/var/lib/containers/storage/sandbox"
	if _, err := os.Stat(storageBase); err != nil {
		t.Skipf("no persistent disk storage base at %s: %v", storageBase, err)
	}
	layerName := "keg-itest-" + strings.TrimPrefix(filepath.Base(t.TempDir()), "Test")
	defer os.RemoveAll(filepath.Join(storageBase, layerName))

	dir := t.TempDir()
	findBwrap(t)
	if err := os.WriteFile(filepath.Join(dir, ".keg.yaml"), []byte(repoConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(storageBase, layerName)
	for _, sub := range []string{"rw", "work"} {
		if err := os.MkdirAll(filepath.Join(layer, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	runLayered := func(script string) string {
		var out bytes.Buffer
		plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayDisk,
			[]string{"/bin/sh", "-c", script})
		if err != nil {
			t.Fatal(err)
		}
		plan.DiskLayerRW = filepath.Join(layer, "rw")
		plan.DiskLayerWork = filepath.Join(layer, "work")
		plan.Stdout = &out
		plan.Stderr = &out
		sb, err := orchestrator.Launch(context.Background(), plan)
		if err != nil {
			t.Fatalf("launch: %v", err)
		}
		code, err := sb.Wait()
		sb.Close()
		if err != nil || code != 0 {
			t.Fatalf("layered run failed: code=%d err=%v\n%s", code, err, out.String())
		}
		return out.String()
	}

	runLayered(`echo persisted > layer.txt && cat layer.txt`)

	// Host repo stays clean; the write lives in the layer.
	if _, err := os.Stat(dir + "/layer.txt"); !os.IsNotExist(err) {
		t.Errorf("disk-overlay write must stay in the layer, not the host repo")
	}

	// A fresh sandbox on the same layer sees the previous run's data.
	got := runLayered(`cat layer.txt`)
	if strings.TrimSpace(got) != "persisted" {
		t.Errorf("persistent layer lost data across exits: got %q", got)
	}
}

// TestSandboxHostEnvStripped proves host credentials do not cross the
// boundary even when present in the orchestrator's environment.
func TestSandboxHostEnvStripped(t *testing.T) {
	t.Setenv("AWS_SESSION_TOKEN", "host-secret")
	t.Setenv("HTTPS_PROXY", "http://corp:3128")
	dir := t.TempDir()
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain,
		`printf "%s|%s" "${AWS_SESSION_TOKEN-EMPTY}" "${HTTPS_PROXY-EMPTY}"`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}
	if out != "EMPTY|EMPTY" {
		t.Errorf("host env leaked into sandbox: %q", out)
	}
}
