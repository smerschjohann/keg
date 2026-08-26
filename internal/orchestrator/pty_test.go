package orchestrator

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/moby/sys/reexec"
)

// TestPTY_IsTTY verifies that isTerminal correctly identifies a non-terminal
// (pipes are not terminals).
func TestPTY_IsTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if isTerminal(r) {
		t.Error("isTerminal(pipe read end) = true, want false")
	}
	if isTerminal(w) {
		t.Error("isTerminal(pipe write end) = true, want false")
	}
}

// TestPTY_OpenPTY verifies that openPTY returns a functional master/slave pair:
// bytes written to the slave are readable on the master.
func TestPTY_OpenPTY(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	if !isTerminal(slave) {
		t.Error("openPTY slave is not a terminal")
	}

	payload := []byte("hello pty\n")
	if _, err := slave.Write(payload); err != nil {
		t.Fatalf("slave write: %v", err)
	}
	// reads from master echo what was written to slave
	buf := make([]byte, 64)
	_ = master.SetReadDeadline(time.Now().Add(time.Second))
	n, err := master.Read(buf)
	if err != nil {
		t.Fatalf("master read: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "hello pty") {
		t.Errorf("master read = %q, want to contain \"hello pty\"", got)
	}
}

// TestRunGuestCommand_WithPTY exercises runGuestCommandPTY: the child sees a
// proper terminal (isatty returns true inside the sandbox command). This is
// the regression test for the interactive TUI bug: without PTY propagation,
// bash -i and TUI apps like agy fail to render properly.
func TestRunGuestCommand_WithPTY(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	// The child checks whether its own stdin is a terminal and prints yes/no.
	argv := []string{"/bin/sh", "-c", `if [ -t 0 ]; then printf "is-tty"; else printf "no-tty"; fi`}
	done := make(chan int, 1)
	go func() {
		done <- runGuestCommandWithStdio(argv, slave, slave, slave)
	}()

	var out bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64)
		for {
			_ = master.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := master.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runGuestCommandWithStdio timed out")
	}
	slave.Close() // EOF for the reader
	<-readDone

	got := out.String()
	if !strings.Contains(got, "is-tty") {
		t.Errorf("child did not see a terminal: got %q", got)
	}
}

// TestGuestCommand_PTYForwardedOnTTY verifies the full guest path: when
// reexec runs the guest with a slave PTY as stdin, the workload receives a
// terminal on its stdin.
func TestGuestCommand_PTYForwardedOnTTY(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c",
		`if [ -t 0 ]; then printf "tty-ok"; else printf "tty-fail"; fi`)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave

	var masterOut bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64)
		for {
			_ = master.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, rerr := master.Read(buf)
			if n > 0 {
				masterOut.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()

	err = cmd.Run()
	slave.Close()
	<-readDone

	if err != nil {
		t.Logf("guest run error: %v", err)
	}
	got := masterOut.String()
	if !strings.Contains(got, "tty-ok") {
		// Also accept reading from slave directly (non-PTY relay path).
		t.Errorf("workload did not see tty: got %q", got)
	}
}

// TestPTY_WindowSizePropagate verifies that setWindowSize does not error when
// called on the master PTY (sanity check for TIOCSWINSZ path).
func TestPTY_WindowSizePropagate(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	if err := setWindowSize(master, 80, 24); err != nil {
		t.Errorf("setWindowSize: %v", err)
	}
}

// TestPTY_NoopOnNonTTY verifies that runGuestCommand (which calls
// runGuestCommandMaybePTY) falls back to plain pipes when stdin is not a
// terminal, preserving the existing non-interactive behaviour.
func TestPTY_NoopOnNonTTY(t *testing.T) {
	// stdin is a pipe → not a terminal → no PTY allocated.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	_ = w.Close()
	defer r.Close()

	// Override os.Stdin so runGuestCommandMaybePTY sees a pipe.
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	var out bytes.Buffer
	argv := []string{"/bin/sh", "-c", "printf non-interactive"}
	code := runGuestCommandMaybePTY(argv, &out, &out)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "non-interactive") {
		t.Errorf("output = %q, want non-interactive", out.String())
	}
}

// compile-time guard that exec is in scope (used by TestRunGuestCommand_ExitCodes).
var _ = exec.Command
