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
	"github.com/smerschjohann/keg/internal/landlock"
	"github.com/smerschjohann/keg/internal/portsfw"
	"github.com/smerschjohann/keg/internal/runner"

	"github.com/moby/sys/reexec"
	"golang.ngrok.com/muxado"
)

// EnvProxyBridge marks a live egress-proxy session on fd FDProxy. Its value
// is the loopback address for the guest bridge (set via bwrap --setenv by
// the orchestrator when the repo whitelist is non-empty).
const EnvProxyBridge = "KEG_PROXY"

// EnvPortsForward marks a live port back-channel on fd FDPorts. Its value
// is the comma-separated allowlist of guest target ports — the guest
// forwarder refuses every target outside it (THREAT_MODEL §5.8,
// deny-by-default).
const EnvPortsForward = "KEG_PORTS"

// EnvLandlock carries the configured Landlock LSM enforcement mode.
const EnvLandlock = "KEG_LANDLOCK"

// GuestCommandName is the reexec name under which the sandbox entrypoint
// runs (second invocation of the same binary inside bwrap).
const GuestCommandName = "github.com/smerschjohann/keg/guest"

func init() {
	reexec.Register(GuestCommandName, guestMain)
}

// guestArgs returns the workload argv for the two supported entrypoint
// shapes: classic reexec (argv[0] = guest name) and the bwrap-bound binary
// (argv[1] = guest name). ok=false when no guest dispatch is present.
func guestArgs() ([]string, bool) {
	if len(os.Args) > 1 && os.Args[0] == GuestCommandName {
		return os.Args[1:], true
	}
	if len(os.Args) > 2 && os.Args[1] == GuestCommandName {
		return os.Args[2:], true
	}
	return nil, false
}

// guestMain is the sandbox-side entrypoint (CODE_KEG=1 invocation).
// Unlike the host process it stays RESIDENT: channel bridges must serve
// requests while the workload runs. It therefore starts the bridges per the
// orchestrator's env markers, spawns the requested command as a child,
// forwards termination signals to it, and mirrors its exit code.
//
// FD contract: fd 3 = proxy channel, fd 4 = DNS, fd 5 = runner,
// fd 6 = port back-channel (see FDProxy/FDDNS/FDRunner/FDPorts).
func guestMain() {
	prepareGuestProcess()

	// Channel bridges live for the whole resident lifetime; they must be
	// started here (NOT in a helper with its own defer) so they survive
	// until the workload exits.
	stopBridges := startConfiguredBridges()
	defer stopBridges()

	argv, ok := guestArgs()
	if !ok {
		fmt.Fprintln(os.Stderr, "keg guest: no command given")
		os.Exit(127)
	}
	code := runGuestCommand(argv)
	os.Exit(code)
}

// prepareGuestProcess applies env hygiene before anything else runs.
func prepareGuestProcess() {
	_ = os.Setenv("CODE_KEG", "1") // best effort; nothing depends on failure modes

	// Unlike hard-closing, CLOEXEC marking cannot disturb runtime-internal
	// descriptors (the full keg binary owns netpoll fds by now), while
	// still guaranteeing the workload child inherits exactly stdio — the
	// channel sockets stay exclusive to this resident process.
	if err := ScrubForeignFDs(map[int]bool{}); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: fd scrub: %v\n", err)
	}

	// Defense-in-depth env hygiene: even if bwrap-side stripping were
	// bypassed, host credentials never reach the workload (THREAT_MODEL §8.2).
	for _, name := range HostDeniedEnvVars {
		_ = os.Unsetenv(name)
	}

	// Re-apply the orchestrator's egress config on top of the stripped
	// environment: the KEG_PROXY marker is the single source of truth,
	// so injected proxy variables survive hygiene while any host proxy
	// values stay gone.
	applyProxyEnv()

	// Landlock LSM defense-in-depth filesystem restrictions (CONCEPT.md §6.1).
	applyLandlock()
}

func applyLandlock() {
	modeStr := os.Getenv(EnvLandlock)
	_ = os.Unsetenv(EnvLandlock)
	if modeStr == "" {
		modeStr = "auto"
	}
	mode := landlock.Mode(modeStr)
	if mode == landlock.ModeOff {
		return
	}
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/sandbox"
	}
	cwd, _ := os.Getwd()
	writable := []string{"/tmp", home}
	if cwd != "" {
		writable = append(writable, cwd)
	}
	cfg := landlock.RulesetConfig{
		Mode:         mode,
		ReadOnlyDirs: []string{"/"},
		WritableDirs: writable,
	}
	if err := landlock.Restrict(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: landlock: %v\n", err)
	}
}

// startConfiguredBridges starts every guest-side bridge requested by env
// marker. Returns a stop function that is always safe to call.
func startConfiguredBridges() func() {
	var stops []func()
	if addr := os.Getenv(EnvProxyBridge); addr != "" && addr != "0" {
		stops = append(stops, startProxyBridgeFromFD(FDProxy, addr))
	}
	if marker := os.Getenv(EnvPortsForward); marker != "" {
		stops = append(stops, startPortForwarderFromFD(FDPorts, marker))
	}
	if os.Getenv(EnvDelegation) == "1" {
		stops = append(stops, startRunnerBridgeFromFD(FDRunner))
	}
	return func() {
		for _, stop := range stops {
			stop()
		}
	}
}

// startRunnerBridgeFromFD serves the guest end of delegation channel C:
// it binds /run/keg/runner.sock in the sandbox and pipes each workload
// connection onto its own stream of fd FDRunner.
func startRunnerBridgeFromFD(fd int) func() {
	file := os.NewFile(uintptr(fd), "keg-runner-channel")
	if file == nil {
		fmt.Fprintf(os.Stderr, "keg guest: runner channel fd %d missing\n", fd)
		return func() {}
	}
	sess := muxado.Client(file, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runner.ServeGuestSocket(ctx, sess)
	}()
	return func() {
		cancel() // closes session first (see Bridge teardown ordering), then unwinds
		<-done
	}
}

// startPortForwarderFromFD serves the guest end of the port back-channel:
// each host-initiated stream names its sandbox loopback target; targets
// outside the declared marker are closed without dialing (fail-closed).
func startPortForwarderFromFD(fd int, allowedMarker string) func() {
	allowed, err := portsfw.ParseAllowed(allowedMarker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: %v\n", err)
		return func() {}
	}
	file := os.NewFile(uintptr(fd), "keg-ports-channel")
	if file == nil {
		fmt.Fprintf(os.Stderr, "keg guest: ports channel fd %d missing\n", fd)
		return func() {}
	}
	sess := muxado.Client(file, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = portsfw.ServeGuest(ctx, sess, allowed, nil)
	}()
	return func() {
		cancel() // closes the session first, then unwinds ServeGuest
		<-done
	}
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

// InitGuestDispatch is the single reentry gate for keg binaries: it
// handles both classic reexec (argv[0] = guest name) and argv[1] dispatch
// for the netns stage and the bwrap-bound guest (see BuildArgs). Returns
// true when this process IS a sandbox component and never returns from it.
func InitGuestDispatch() bool {
	if len(os.Args) > 1 && os.Args[1] == NetnsStageCommandName {
		netnsStageMain()
		return true
	}
	if len(os.Args) > 1 && os.Args[1] == GuestCommandName {
		guestMain()
		return true
	}
	return reexec.Init()
}

// RunGuest exposes the sandbox entrypoint to cmd/keg main.
func RunGuest() { guestMain() }

// applyProxyEnv derives the proxy variables from the bridge marker. Values
// point exclusively at loopback (TestInvariant_ProxyEnvNeverPointsOffLoopback).
func applyProxyEnv() {
	addr := os.Getenv(EnvProxyBridge)
	if addr == "" || addr == "0" {
		return
	}
	url := "http://" + addr
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		_ = os.Setenv(name, url)
	}
	_ = os.Setenv("NO_PROXY", "localhost,127.0.0.1")
	_ = os.Setenv("no_proxy", "localhost,127.0.0.1")
}
