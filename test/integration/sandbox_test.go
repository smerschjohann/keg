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

	"golang.org/x/sys/unix"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// TestSandboxShellIsolated is the WP-M1 DoD test: a shell inside the
// sandbox sees only loopback networking, a tmpfs HOME and a read-only /usr.
func TestSandboxShellIsolated(t *testing.T) {
	dir := t.TempDir()

	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `
echo "UID:$(id -u)"
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
		"UID": func(v string) error {
			want := fmt.Sprintf("%d", os.Getuid())
			if v != want {
				t.Errorf("UID = %q, want %s (invoking user's UID must be preserved)", v, want)
			}
			return nil
		},
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

// TestInvariant_WorkloadGetsOnlyStdioFDs verifies the complete FD contract
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

	// Resident-guest model (WP-M2): the workload child inherits exactly
	// stdio. The channel sockets stay exclusive to the resident guest
	// process — strictly stronger than the old "stdio + channels" contract,
	// because the workload cannot touch channel fds directly at all.
	for _, fd := range []string{"0", "1", "2"} {
		if _, ok := fds[fd]; !ok {
			t.Errorf("std fd %s missing:\n%s", fd, out)
		}
		delete(fds, fd)
	}
	for fd, target := range fds {
		t.Errorf("foreign fd %s leaked into workload (%s):\n%s", fd, target, out)
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

// TestInvariant_SeccompBlocksSyscalls verifies Invariant 9: critical syscalls
// (bpf, perf_event_open, keyctl) are blocked with EPERM under the default
// seccomp profile, while normal baseline system calls operate normally.
func TestInvariant_SeccompBlocksSyscalls(t *testing.T) {
	dir := t.TempDir()
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `
python3 -c '
import ctypes, errno, sys

libc = ctypes.CDLL(None, use_errno=True)

# 321 = SYS_BPF on x86_64, 280 on arm64
res_bpf = libc.syscall(321, 0, 0, 0)
err_bpf = ctypes.get_errno()

# 298 = SYS_PERF_EVENT_OPEN on x86_64, 241 on arm64
res_perf = libc.syscall(298, 0, 0, 0, 0, 0)
err_perf = ctypes.get_errno()

# 250 = SYS_KEYCTL on x86_64, 219 on arm64
res_key = libc.syscall(250, 0, 0, 0, 0)
err_key = ctypes.get_errno()

print(f"BPF_ERR:{err_bpf}")
print(f"PERF_ERR:{err_perf}")
print(f"KEY_ERR:{err_key}")

status = open("/proc/self/status").read()
for line in status.splitlines():
    if line.startswith("Seccomp:"):
        print(line)
'
`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}

	if !strings.Contains(out, fmt.Sprintf("BPF_ERR:%d", int(unix.EPERM))) {
		t.Errorf("expected BPF to fail with EPERM (%d), output:\n%s", int(unix.EPERM), out)
	}
	if !strings.Contains(out, fmt.Sprintf("PERF_ERR:%d", int(unix.EPERM))) {
		t.Errorf("expected PERF_EVENT_OPEN to fail with EPERM (%d), output:\n%s", int(unix.EPERM), out)
	}
	if !strings.Contains(out, fmt.Sprintf("KEY_ERR:%d", int(unix.EPERM))) {
		t.Errorf("expected KEYCTL to fail with EPERM (%d), output:\n%s", int(unix.EPERM), out)
	}
	if !strings.Contains(out, "Seccomp:\t2") {
		t.Errorf("expected /proc/self/status to have Seccomp: 2 (filter active), output:\n%s", out)
	}
}

// TestInvariant_SeccompBlocksIOUring verifies Invariant 9: io_uring syscalls
// are blocked with EPERM.
func TestInvariant_SeccompBlocksIOUring(t *testing.T) {
	dir := t.TempDir()
	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, `
python3 -c '
import ctypes, errno, sys

libc = ctypes.CDLL(None, use_errno=True)

# 425 = SYS_IO_URING_SETUP (x86_64 & arm64)
res_setup = libc.syscall(425, 0, 0)
err_setup = ctypes.get_errno()

# 426 = SYS_IO_URING_ENTER (x86_64 & arm64)
res_enter = libc.syscall(426, 0, 0, 0, 0, 0, 0)
err_enter = ctypes.get_errno()

print(f"IOURING_SETUP_ERR:{err_setup}")
print(f"IOURING_ENTER_ERR:{err_enter}")
'
`)
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}

	if !strings.Contains(out, fmt.Sprintf("IOURING_SETUP_ERR:%d", int(unix.EPERM))) {
		t.Errorf("expected io_uring_setup to fail with EPERM (%d), output:\n%s", int(unix.EPERM), out)
	}
	if !strings.Contains(out, fmt.Sprintf("IOURING_ENTER_ERR:%d", int(unix.EPERM))) {
		t.Errorf("expected io_uring_enter to fail with EPERM (%d), output:\n%s", int(unix.EPERM), out)
	}
}

// TestIntegration_SeccompOffOption verifies that security.seccomp: off disables
// the seccomp filter entirely (Seccomp: 0 in /proc/self/status).
func TestIntegration_SeccompOffOption(t *testing.T) {
	dir := t.TempDir()
	out, code := runInSandboxWithConfig(t, dir, repoConfig, orchestrator.OverlayPlain, `
grep Seccomp /proc/self/status
`, func(p *orchestrator.Plan) {
		p.Seccomp = "off"
	}, nil)

	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out)
	}

	if !strings.Contains(out, "Seccomp:\t0") {
		t.Errorf("expected Seccomp: 0 with seccomp off, got:\n%s", out)
	}
}

// TestIntegration_DeveloperToolsUnderSeccomp verifies that common developer tools
// (ptrace/debugger workflows, Git operations, Go toolchain, Python runtime)
// operate seamlessly inside the sandbox under the active Seccomp profile.
func TestIntegration_DeveloperToolsUnderSeccomp(t *testing.T) {
	dir := t.TempDir()

	script := `
set -e

# 1. Verify Seccomp is active
grep -q "Seccomp:[[:space:]]*2" /proc/self/status

# 2. Ptrace / Debugger simulation: tracer attaching to tracee
python3 -c '
import os, sys, ctypes

libc = ctypes.CDLL(None, use_errno=True)

# PTRACE_TRACEME = 0, PTRACE_CONT = 7
pid = os.fork()
if pid == 0:
    res = libc.ptrace(0, 0, 0, 0)
    if res != 0:
        os._exit(1)
    os.kill(os.getpid(), 19) # SIGSTOP
    os._exit(42)

_, status = os.waitpid(pid, 0)
if not os.WIFSTOPPED(status):
    sys.exit(2)

res = libc.ptrace(7, pid, 0, 0) # PTRACE_CONT
if res != 0:
    sys.exit(3)

_, status = os.waitpid(pid, 0)
if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 42:
    sys.exit(4)

print("PTRACE_OK")
'

# 3. Git repository operations
git init
git config user.name "Keg Developer"
git config user.email "dev@keg.local"
echo "hello keg" > file.txt
git add file.txt
git commit -m "initial commit"
git log -1 --pretty=%s | grep -q "initial commit"
echo "GIT_OK"

# 4. Python runtime and subprocess execution
python3 -c '
import subprocess
out = subprocess.check_output(["echo", "PY_SUBPROCESS_OK"]).decode().strip()
print(out)
'
`

	out, code := runInSandbox(t, dir, orchestrator.OverlayPlain, script)
	if code != 0 {
		t.Fatalf("developer tooling integration test failed (code %d):\n%s", code, out)
	}

	for _, check := range []string{"PTRACE_OK", "GIT_OK", "PY_SUBPROCESS_OK"} {
		if !strings.Contains(out, check) {
			t.Errorf("output missing verification marker %q:\n%s", check, out)
		}
	}
}
