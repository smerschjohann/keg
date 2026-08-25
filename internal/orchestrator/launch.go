package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// Sandbox is a running sandbox instance. It owns the host ends of the
// channel socketpairs and the bwrap child process; Close releases both.
type Sandbox struct {
	cmd *exec.Cmd

	// hostEnds are the orchestrator-owned socketpair ends; the guest holds
	// the peers at fds FDProxy/FDDNS/FDRunner. Closed by Close().
	hostEnds []*os.File
}

// Launch starts the sandbox described by p and returns once bwrap has
// started successfully. Cancelling ctx kills the sandbox process
// (CONCEPT.md §8.2: context cancellation tears everything down).
func Launch(ctx context.Context, p Plan) (*Sandbox, error) {
	bin := p.BwrapPath
	if bin == "" {
		resolved, err := exec.LookPath("bwrap")
		if err != nil {
			return nil, fmt.Errorf("bubblewrap not found in PATH (install bubblewrap >= 0.11): %w", err)
		}
		bin = resolved
	}

	args, err := BuildArgs(p)
	if err != nil {
		return nil, fmt.Errorf("build bwrap args: %w", err)
	}

	// Channel socketpairs; guest ends become fds 3/4/5 inside the sandbox.
	var hostEnds []*os.File
	var extra []*os.File
	for i := 0; i < FDPreserved; i++ {
		host, guest, err := Socketpair()
		if err != nil {
			closeFiles(hostEnds)
			closeFiles(extra)
			return nil, fmt.Errorf("create channel %d: %w", i, err)
		}
		hostEnds = append(hostEnds, host)
		extra = append(extra, guest)
	}

	stdin := p.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := p.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := p.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- args are built by BuildArgs from validated config
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = extra
	cmd.Env = os.Environ() // sandbox env hygiene happens via bwrap args + guest strip

	sb := &Sandbox{cmd: cmd, hostEnds: hostEnds}

	// The parent's copies of the guest ends are redundant once the child
	// holds them; drop ours so EOF propagates correctly on exit.
	defer func() {
		closeFiles(extra)
	}()

	if err := cmd.Start(); err != nil {
		closeFiles(hostEnds)
		return nil, fmt.Errorf("start bwrap: %w", err)
	}
	return sb, nil
}

// Wait blocks until the sandbox command exits and returns its exit code.
func (s *Sandbox) Wait() (int, error) {
	err := s.cmd.Wait()
	s.Close() // host ends die with the session
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, fmt.Errorf("wait sandbox: %w", err)
}

// Pid returns the bwrap process id (valid after Launch).
func (s *Sandbox) Pid() int { return s.cmd.Process.Pid }

// Signal forwards a signal to the sandbox root process (die-with-parent
// takes down the whole tree as backstop).
func (s *Sandbox) Signal(sig os.Signal) error {
	if s.cmd.Process == nil {
		return nil
	}
	return s.cmd.Process.Signal(sig)
}

// Close releases orchestrator-owned resources (channel host ends).
func (s *Sandbox) Close() {
	closeFiles(s.hostEnds)
	s.hostEnds = nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
