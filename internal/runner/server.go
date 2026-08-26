package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/smerschjohann/keg/internal/frame"

	"golang.ngrok.com/muxado"
)

// ServerConfig wires the host-side delegation daemon (Kanal C). The daemon
// executes whitelisted jobs in the context of the invoking user; sandbox
// values never flow into the job environment — parameters travel as argv
// only (CONCEPT.md §4.5).
type ServerConfig struct {
	Engine *Engine
	// JustBin is the `just` binary for exact/prefix tasks ("just" default).
	JustBin string
	// RepoRoot pins every job inside the host repository (path jail).
	RepoRoot string
	// HooksDir is an empty directory owned by keg; raw git jobs run
	// with core.hooksPath pointed at it so a malicious repo cannot plant
	// host-side hooks (THREAT_MODEL §5.4). Empty disables suppression.
	HooksDir string
	// Audit, if set, receives task execution decisions (allowed, task representation, reason).
	Audit func(allowed bool, task string, reason string)
}

// ServeSession serves jobs over one muxado session (the host end of the
// channel-C socketpair); every accepted stream carries exactly one job.
// It returns when the session closes.
func ServeSession(sess muxado.Session, cfg ServerConfig) error {
	return ServeSessionCtx(context.Background(), sess, cfg)
}

// ServeSessionCtx behaves like ServeSession and tears down all running
// jobs when ctx is cancelled (sandbox exit kills its delegated jobs).
func ServeSessionCtx(ctx context.Context, sess muxado.Session, cfg ServerConfig) error {
	for {
		stream, err := sess.Accept()
		if err != nil {
			// Session closed (sandbox teardown) or transport error: both
			// are ordinary stop conditions for the accept loop.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go handleStream(ctx, stream, cfg)
	}
}

// handleStream runs exactly one job on conn. All outcomes are reported as
// events before close — never as bare transport errors — so the client can
// always map them onto exit codes.
func handleStream(ctx context.Context, conn net.Conn, cfg ServerConfig) {
	defer func() { _ = conn.Close() }()

	payload, err := frame.ReadFrame(conn)
	if err != nil {
		return // client vanished before completing its request
	}
	req, err := DecodeRequest(payload)
	if err != nil || len(req.ArgvB64) == 0 {
		writeEvent(conn, Event{Type: EventError, Message: "malformed job request"})
		return
	}
	argv := DecodeStrings(req.ArgvB64)

	decision := cfg.Engine.Match(argv)
	if cfg.Audit != nil {
		cfg.Audit(decision.Allow, strings.Join(argv, " "), decision.Reason)
	}
	if !decision.Allow {
		writeEvent(conn, Event{Type: EventDenied, Message: decision.Reason})
		return
	}

	dir := cfg.RepoRoot
	if req.Dir != "" {
		dir, err = jailDir(cfg.RepoRoot, req.Dir)
		if err != nil {
			writeEvent(conn, Event{Type: EventError, Message: err.Error()})
			return
		}
	}

	cmd, err := buildCommand(ctx, decision.Kind, argv, dir, cfg)
	if err != nil {
		writeEvent(conn, Event{Type: EventError, Message: err.Error()})
		return
	}
	runJob(ctx, cmd, conn)
}

// jailDir resolves a request-relative working directory against the repo
// root, rejecting anything that escapes it (filepath.Rel check,
// IMPLEMENTATION_PLAN §7.2).
func jailDir(root, sub string) (string, error) {
	if filepath.IsAbs(sub) {
		return "", fmt.Errorf("job dir %q must be relative to the repo root", sub)
	}
	abs := filepath.Join(root, filepath.Clean(sub))
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("job dir %q escapes the repository root", sub)
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return "", fmt.Errorf("job dir %q does not exist in the repository", sub)
	}
	return abs, nil
}

// buildCommand materializes the exec for a decision. Raw commands run via
// PATH lookup with their argv untouched except for git hook suppression;
// just tasks prepend the configured binary.
func buildCommand(ctx context.Context, kind Kind, argv []string, dir string, cfg ServerConfig) (*exec.Cmd, error) {
	switch kind {
	case KindJust:
		bin := cfg.JustBin
		if bin == "" {
			bin = "just"
		}
		cmd := exec.CommandContext(ctx, bin, argv...) // #nosec G204 -- JustBin from trusted user config, args whitelist-matched
		cmd.Dir = dir
		return cmd, nil
	case KindRaw:
		exe, err := exec.LookPath(argv[0])
		if err != nil {
			return nil, fmt.Errorf("raw command %q not found on host PATH", argv[0])
		}
		args := argv[1:]
		// Git-hook suppression: delegating git into the HOST repo would
		// otherwise execute whatever hooks the repo ships (THREAT_MODEL §5.4).
		if filepath.Base(exe) == "git" && cfg.HooksDir != "" {
			args = append([]string{"-c", "core.hooksPath=" + cfg.HooksDir}, args...)
		}
		cmd := exec.CommandContext(ctx, exe, args...) // #nosec G204 -- exe resolved from whitelist-matched argv
		cmd.Dir = dir
		return cmd, nil
	default:
		return nil, fmt.Errorf("unknown execution kind %d", kind)
	}
}

// runJob streams stdout/stderr live, then reports the outcome. Jobs die
// with their process group when the sandbox goes away.
func runJob(ctx context.Context, cmd *exec.Cmd, conn net.Conn) {
	cmd.Dir = firstNonEmpty(cmd.Dir, ".")
	cmd.Env = os.Environ() // host user env only; nothing from the sandbox
	cmd.Stdout = &eventWriter{conn: conn, typ: EventStdout}
	cmd.Stderr = &eventWriter{conn: conn, typ: EventStderr}

	// Kill the whole process group when the context is cancelled or the
	// WaitDelay expires, so grandchildren (test runners etc.) cannot
	// outlive the sandbox connection.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			writeEvent(conn, Event{Type: EventError, Message: "job terminated: sandbox shut down"})
			return
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code := ee.ExitCode()
			if code < 0 {
				// Killed by a signal: mirror shell convention 128+signum.
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					code = 128 + int(ws.Signal())
				} else {
					code = 128
				}
			}
			writeEvent(conn, Event{Type: EventExit, Code: code})
			return
		}
		writeEvent(conn, Event{Type: EventError, Message: err.Error()})
		return
	}
	writeEvent(conn, Event{Type: EventExit, Code: 0})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// eventWriter frames one output chunk per Write call. A mutex serializes
// the two concurrent copy directions onto the single stream.
type eventWriter struct {
	conn io.Writer
	typ  string
	mu   sync.Mutex
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ev := Event{Type: w.typ, Data: base64.StdEncoding.EncodeToString(p)}
	b, err := json.Marshal(ev)
	if err != nil {
		return 0, fmt.Errorf("runner: encode event: %w", err)
	}
	if err := frame.WriteFrame(w.conn, b); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeEvent(conn io.Writer, ev Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return // unreachable for plain strings; dropping beats panicking
	}
	_ = frame.WriteFrame(conn, b)
}
