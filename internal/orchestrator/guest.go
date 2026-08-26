package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/smerschjohann/keg/internal/egress/proxy"

	"github.com/moby/sys/reexec"
	"golang.ngrok.com/muxado"
)

// EnvProxyBridge marks a live egress-proxy session on fd FDProxy. Its value
// is the loopback address for the guest bridge (set via bwrap --setenv by
// the orchestrator when the repo whitelist is non-empty).
const EnvProxyBridge = "KEG_PROXY"

// GuestCommandName is the reexec name under which the sandbox entrypoint
// runs (second invocation of the same binary inside bwrap).
const GuestCommandName = "github.com/smerschjohann/keg/guest"

func init() {
	reexec.Register(GuestCommandName, guestMain)
}

// guestMain is the sandbox-side entrypoint (CODE_KEG=1 invocation).
// Unlike the host process it stays RESIDENT: channel bridges must serve
// requests while the workload runs. It therefore starts the bridges per the
// orchestrator's env markers, spawns the requested command as a child,
// forwards termination signals to it, and mirrors its exit code.
//
// FD contract: fd 3 = proxy channel, fd 4 = DNS, fd 5 = runner
// (see FDProxy/FDDNS/FDRunner).
func guestMain() {
	_ = os.Setenv("CODE_KEG", "1") // best effort; nothing depends on failure modes

	// Defense-in-depth against inherited descriptors (bwrap passes unknown
	// fds through, and its own setup may leave duplicates of our channel
	// sockets behind): keep only stdio and the channel ends.
	if err := CloseAllFDsExcept(0, 1, 2, FDProxy, FDDNS, FDRunner); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: fd cleanup: %v\n", err)
	}

	// Defense-in-depth env hygiene: even if bwrap-side stripping were
	// bypassed, host credentials never reach the workload (THREAT_MODEL §8.2).
	for _, name := range HostDeniedEnvVars {
		_ = os.Unsetenv(name)
	}

	// Channel bridges; each owns its listener and dies with the session.
	stopBridges := startConfiguredBridges()
	defer stopBridges()

	code := runGuestCommand(os.Args[1:])
	os.Exit(code)
}

// startConfiguredBridges starts every guest-side bridge requested by env
// marker. Returns a stop function that is always safe to call.
func startConfiguredBridges() func() {
	var stop func()
	if addr := os.Getenv(EnvProxyBridge); addr != "" && addr != "0" {
		stop = startProxyBridgeFromFD(FDProxy, addr)
	}
	if stop == nil {
		return func() {}
	}
	return stop
}

// startProxyBridgeFromFD wires the channel file into a loopback listener.
// Failures are fatal-ish but non-blocking: the workload still runs, just
// without egress (fail-closed — never fall back to host network access).
func startProxyBridgeFromFD(fd int, addr string) func() {
	file := os.NewFile(uintptr(fd), "keg-proxy-channel")
	if file == nil {
		fmt.Fprintf(os.Stderr, "keg guest: proxy channel fd %d missing\n", fd)
		return func() {}
	}
	ln, err := listenLoopback(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: proxy bridge listen %s: %v\n", addr, err)
		return func() {}
	}
	bridge, sess := startProxyBridge(file, ln)
	go func() { _ = bridge.Serve() }()
	// Session first (unblocks pipes), then listener + in-flight wait.
	return func() {
		_ = sess.Close()
		_ = bridge.Close()
	}
}

// listenLoopback binds the guest-side service address (loopback only by
// construction of the callers).
func listenLoopback(addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp", addr)
}

// startProxyBridge attaches a muxado client session over the channel file
// and exposes it behind ln. The returned session MUST be closed before the
// listener/bridge teardown: closing the transport wakes all streams, which
// lets the bridge's pipe goroutines unwind (raw socketpair fds are not
// poller-managed, so closing the file alone would leave them blocked).
func startProxyBridge(file *os.File, ln net.Listener) (*proxy.Bridge, muxado.Session) {
	sess := muxado.Client(file, nil)
	return proxy.NewBridge(sess, ln), sess
}

// runGuestCommand spawns argv as child, forwards signals, waits and maps
// the result onto conventional exit codes: child code verbatim, signal
// death as 128+signum, spawn failure or exec errors as 127.
func runGuestCommand(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "keg guest: no command given")
		return 127
	}
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...) // #nosec G702 -- trusted caller (host-side orchestrator); arbitrary argv is the whole point
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: exec %s: %v\n", argv[0], err)
		return 127
	}
	// The resident guest acts as init-like wrapper: signals aimed at the
	// sandbox (SIGINT from the tty, SIGTERM from the orchestrator) belong
	// to the workload, so catch them here and forward.
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGCHLD {
				continue // reaped by cmd.Wait, not part of the workload
			}
			_ = cmd.Process.Signal(sig)
		}
	}()

	err := cmd.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		fmt.Fprintf(os.Stderr, "keg guest: wait %s: %v\n", argv[0], err)
		return 127
	}
	if code := ee.ExitCode(); code >= 0 {
		return code
	}
	// Signaled: mirror shell convention 128+signum.
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 127
	}
	return 128 + int(ws.Signal())
}
