package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Sandbox is a running sandbox instance. It owns the host ends of the
// channel socketpairs and the bwrap child process; Close releases both.
type Sandbox struct {
	closeMu sync.Mutex
	closed  bool

	cmd *exec.Cmd

	waitCh chan waitResult

	// hostEnds are the orchestrator-owned socketpair ends; the guest holds
	// the peers at fds FDProxy/FDDNS/FDRunner/FDPorts. Closed by Close().
	hostEnds []*os.File

	// portListeners are the channel-E host listeners started by
	// StartPortsForward; released by Close BEFORE the host ends die
	// (session/streams first via end closure, then listeners).
	portListeners []net.Listener

	raw    *rawEndpoints // ip->endpoint correlation (transparent mode)
	rawCfg rawCfg
}

type waitResult struct {
	code   int
	err    error
	stderr string // captured only when an overlay mount is involved
}

// Launch starts the sandbox described by p and returns once bwrap has
// started successfully AND survived its setup phase: bubblewrap performs
// all mounts before executing the command, so early exits surface mount
// errors here rather than in Wait.
func Launch(ctx context.Context, p Plan) (*Sandbox, error) {
	// Route the workload through the reexec guest unless the caller pinned
	// a binary path (tests inject stubs). /proc/self/exe is stable across
	// binary replacement (moby/sys/reexec Self semantics).
	if p.SelfExe == "" {
		if exe, err := os.Readlink("/proc/self/exe"); err == nil {
			p.SelfExe = exe
		}
	}

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

	const (
		maxAttempts   = 10
		retryInterval = 500 * time.Millisecond
		stableWindow  = 750 * time.Millisecond // mounts happen before command exec
	)

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		sb, startErr := start(ctx, bin, args, p)
		if startErr != nil {
			closeFiles(sb.hostEnds)
			return nil, startErr // pre-start failures are not retryable races
		}
		{
			// Give bwrap time to reach the command execution: mount
			// failures kill it within milliseconds of Start(), BEFORE the
			// command runs. A command that finishes inside the stability
			// window exits 0 — also fine, just early.
			select {
			case res := <-sb.waitCh:
				closeFiles(sb.hostEnds)
				if isOverlayBusy(res) {
					lastErr = fmt.Errorf("bwrap overlay mount busy: %s", res.stderr)
					break // transient race: retry with a fresh attempt
				}
				sb.waitCh <- res // not ours to judge: hand the real result back
				return sb, nil
			case <-time.After(stableWindow):
				return sb, nil // alive past setup: hand over to caller
			case <-ctx.Done():
				_ = sb.cmd.Process.Kill()
				closeFiles(sb.hostEnds)
				return nil, ctx.Err()
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryInterval):
		}
	}
	return nil, fmt.Errorf("sandbox did not become stable after %d attempts: %w", maxAttempts, lastErr)
}

// isOverlayBusy classifies an early-exit result as the transient overlay
// workdir race. Detection relies on this exact stderr pattern because bwrap
// uses plain exit code 1 for all setup failures — a workload exiting 1
// quickly would be indistinguishable by code alone.
func isOverlayBusy(res waitResult) bool {
	return strings.Contains(res.stderr, "Can't make overlay mount") &&
		strings.Contains(res.stderr, "Device or resource busy")
}

// lockedWriter serializes writes across exec's stdout/stderr copy
// goroutines.
type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// start performs one sandbox launch attempt through the netns stage. On
// success the process is being monitored; its eventual result is delivered
// on sb.waitCh exactly once.
func start(ctx context.Context, bin string, args []string, p Plan) (*Sandbox, error) {
	// The netns stage wraps bwrap: it creates the private user+network
	// namespace, prepares loopback and serves channel B (:53), then execs
	// bwrap so the sandbox shares that namespace. Channel A keeps its own
	// socketpair (fd 3); fd 4/5 stay reserved for future channels.
	stage := &stageConfig{BwrapPath: bin, Args: args, DNS: p.EgressDNS, Transparent: p.Transparent}
	if p.Transparent {
		ip, err := OutboundIPv4()
		if err != nil {
			return nil, fmt.Errorf("transparent mode: %w", err)
		}
		stage.OutboundIP = ip
	}
	if len(p.TCPEndpoints) > 0 {
		var ports []int
		for _, ep := range p.TCPEndpoints {
			ports = append(ports, ep.Ports...)
		}
		stage.TransparentPorts = ports
	}
	unshareBin, err := findUnshare()
	if err != nil {
		return nil, err
	}
	selfExe := p.SelfExe
	if selfExe == "" { // direct bwrap fallback (focused unit tests only)
		stage.Args = args
	}
	stageSelf := p.SelfExe

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

	var argv []string
	var envJSON string
	if stageSelf != "" {
		var uerr error
		argv, envJSON, uerr = unshareStageArgv(unshareBin, stageSelf, stage)
		if uerr != nil {
			closeFiles(hostEnds)
			closeFiles(extra)
			return nil, uerr
		}
	}

	// exec.Cmd copies stdout and stderr from dedicated goroutines; when
	// callers pass the same stream for both (common in tests), writes must
	// be serialized to stay race-free.
	var streamMu sync.Mutex
	safeStdout := lockedWriter{w: stdout, mu: &streamMu}
	safeStderr := lockedWriter{w: stderr, mu: &streamMu}

	// ctx cancellation kills the process (CONCEPT.md §8.2); the stable-
	// window check in Launch additionally catches early setup deaths.
	var cmd *exec.Cmd
	if len(argv) > 0 {
		// Stage path: unshare(1) execs this binary as the netns stage,
		// which prepares loopback/DNS :53 and then execs bwrap.
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- assembled from validated config + trusted self path
		cmd.Env = append(os.Environ(), stageEnvVar+"="+envJSON)
	} else {
		// Direct bwrap fallback for focused unit tests without SelfExe.
		cmd = exec.CommandContext(ctx, bin, args...) // #nosec G204 -- args are built by BuildArgs from validated config
	}
	cmd.Stdin = stdin
	cmd.Stdout = safeStdout
	cmd.ExtraFiles = extra
	if cmd.Env == nil {
		cmd.Env = os.Environ() // sandbox env hygiene happens via bwrap args + guest strip
	}

	// Capture stderr to detect the overlay EBUSY race while still passing
	// it through to the caller's stream.
	var errBuf bytes.Buffer
	if p.HasOverlay() {
		cmd.Stderr = io.MultiWriter(safeStderr, &errBuf)
	} else {
		cmd.Stderr = safeStderr
	}

	// FD hygiene: bwrap passes unknown descriptors through to the child
	// (bubblewrap.c: "Any other fds will be passed on to the child though"),
	// so mark everything except stdio and our channel ends as close-on-exec
	// before starting it. THREAT_MODEL §5.1 (fd-leak audit).
	keep := map[int]bool{0: true, 1: true, 2: true}
	for _, f := range extra {
		keep[int(f.Fd())] = true
	}
	for _, fd := range p.KeepFDs {
		keep[fd] = true
	}
	if err := ScrubForeignFDs(keep); err != nil {
		closeFiles(hostEnds)
		closeFiles(extra)
		return nil, fmt.Errorf("scrub foreign fds: %w", err)
	}

	sb := &Sandbox{cmd: cmd, hostEnds: hostEnds}

	// The parent's copies of the guest ends are redundant once the child
	// holds them; drop ours so EOF propagates correctly on exit.
	defer closeFiles(extra)

	if err := cmd.Start(); err != nil {
		closeFiles(hostEnds)
		return nil, fmt.Errorf("start bwrap: %w", err)
	}

	sb.waitCh = make(chan waitResult, 1)
	go func() {
		err := cmd.Wait()
		sb.Close() // host ends die with the session
		res := waitResult{code: 0}
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				// Normal exit (incl. signal deaths: code < 0).
				res.code = ee.ExitCode()
			} else {
				res.err = err
			}
		}
		res.stderr = errBuf.String()
		sb.waitCh <- res
	}()
	return sb, nil
}

// Wait blocks until the sandbox command exits and returns its exit code.
func (s *Sandbox) Wait() (int, error) {
	res := <-s.waitCh
	return res.code, res.err
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

// Close releases orchestrator-owned resources: the port back-channel
// listeners first, then the channel host ends (whose closure unwinds the
// muxado sessions and every stream riding on them).
func (s *Sandbox) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	listeners := s.portListeners
	s.portListeners = nil
	ends := s.hostEnds
	s.hostEnds = nil
	s.closeMu.Unlock()

	for _, ln := range listeners {
		_ = ln.Close()
	}
	closeFiles(ends)
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
