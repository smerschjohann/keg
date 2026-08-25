//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestInvariant_OnlyPlannedFDsInherit verifies the complete FD contract
// inside the sandbox: exactly fds 0-2 (stdio) plus the channel ends 3-5 as
// socketpair sockets — nothing else. Foreign host descriptors are marked
// close-on-exec before start (THREAT_MODEL §5.1), so any extra entry here
// is a leak that made it through.
func TestInvariant_OnlyPlannedFDsInherit(t *testing.T) {
	dir := t.TempDir()
	script := `for f in /proc/self/fd/*; do printf "%s=%s\n" "$(basename $f)" "$(readlink $f)"; done`
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, script)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}

	fds := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && v != "" { // skip the scanner's own dirfd (empty target)
			fds[k] = v
		}
	}

	channelInodes := map[string]bool{} // inode -> true, from fds 3..5
	for _, fd := range []string{"0", "1", "2"} {
		if _, ok := fds[fd]; !ok {
			t.Errorf("std fd %s missing:\n%s", fd, out)
		}
		delete(fds, fd)
	}
	for _, fd := range []string{"3", "4", "5"} {
		target, ok := fds[fd]
		if !ok {
			t.Errorf("channel fd %s missing:\n%s", fd, out)
			continue
		}
		delete(fds, fd)
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		channelInodes[inode] = true
		if !strings.HasPrefix(target, "socket:[") {
			t.Errorf("fd %s = %q, want a socketpair end\n%s", fd, target, out)
		}
	}
	// Anything left must be a duplicate of a channel socket (bwrap's own
	// setup dups the preserved ends); any file, pipe or other socket here
	// is a leak that escaped both the host-side CLOEXEC scrub and the
	// guest-side close sweep.
	for fd, target := range fds {
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if !strings.HasPrefix(target, "socket:[") || !channelInodes[inode] {
			t.Errorf("foreign fd %s leaked into sandbox (%s):\n%s", fd, target, out)
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
	// Unique per run: a leftover kernel reference (detached overlay mount
	// from an earlier run on the same path) surfaces as EBUSY otherwise.
	layerName := fmt.Sprintf("keg-itest-%d", time.Now().UnixNano())
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

	// A fresh sandbox on the same layer sees the previous run's data. The
	// output may contain a retry preamble from a transient EBUSY attempt,
	// hence substring matching.
	got := runLayered(`cat layer.txt`)
	if !strings.Contains(got, "persisted") {
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
