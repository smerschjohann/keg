package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/smerschjohann/keg/internal/egress/dns"

	"golang.ngrok.com/muxado"

	"github.com/moby/sys/reexec"
)

// NetnsStageCommandName is the reexec name of the netns stage: it runs
// inside a user+network namespace owned by keg (created by unshare(1)),
// prepares the network (loopback up, low ports allowed), serves the DNS
// resolver on loopback :53 and finally execs bwrap so the sandbox shares
// this namespace.
const NetnsStageCommandName = "github.com/smerschjohann/keg/netns-stage"

// stageEnvVar carries the marshalled stageConfig into the stage process.
const stageEnvVar = "KEG_STAGE"

// stageConfig is everything the stage needs before exec'ing bwrap.
type stageConfig struct {
	BwrapPath   string     `json:"bwrap_path"`
	Args        []string   `json:"args"`
	DNS         *DNSConfig `json:"dns,omitempty"`
	Transparent bool       `json:"transparent,omitempty"`
	// OutboundIP pins the host's egress IPv4 on loopback inside the stage
	// namespace (valid source address selection); empty skips the step.
	OutboundIP string `json:"outbound_ip,omitempty"`
	// TransparentPorts are the tcp_endpoints ports nftables redirects to
	// the raw relay (:443 is redirected for SNI traffic independently).
	TransparentPorts []int `json:"transparent_ports,omitempty"`
}

func init() {
	// Both dispatch names share the registry; the stage is dispatched via
	// argv[1] (see InitGuestDispatch), the guest additionally via argv[0].
	reexec.Register(NetnsStageCommandName, netnsStageMain)
}

// findUnshare locates util-linux unshare(1); it performs the actual
// namespace creation because Go processes cannot unshare(CLONE_NEWUSER).
func findUnshare() (string, error) {
	path, err := exec.LookPath("unshare")
	if err != nil {
		return "", fmt.Errorf("util-linux 'unshare' not found in PATH (required for the network stage): %w", err)
	}
	return path, nil
}

// unshareStageArgv assembles the unshare(1) invocation wrapping the stage:
// a private user+network namespace mapped to the invoking user, with
// --keep-caps so the stage can configure the network before dropping all
// capabilities again prior to exec'ing bwrap. The returned envJSON must be
// attached as KEG_STAGE to the child environment.
func unshareStageArgv(unshareBin, selfExe string, cfg *stageConfig) ([]string, string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("marshal stage config: %w", err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	return []string{
		unshareBin,
		"-U",
		fmt.Sprintf("--map-users=%d:%d:1", uid, uid),
		fmt.Sprintf("--map-groups=%d:%d:1", gid, gid),
		"-n",
		"-m",
		"-p",
		"--fork",
		"--keep-caps",
		selfExe,
		NetnsStageCommandName,
	}, string(raw), nil
}

// netnsStageMain runs inside the wrapper namespace: prepare the network,
// serve DNS on :53 when configured, then exec bwrap. Never returns.
func netnsStageMain() {
	cfgRaw := os.Getenv(stageEnvVar)
	var cfg stageConfig
	if err := json.Unmarshal([]byte(cfgRaw), &cfg); err != nil || len(cfg.Args) == 0 {
		fmt.Fprintf(os.Stderr, "keg netns stage: bad config: %v\n", err)
		os.Exit(125)
	}

	// Mount a fresh /proc private to our user+pid namespace. In container
	// environments where the parent mount namespace has a read-only /proc/sys,
	// this gives the stage and bwrap a writable /proc/sys for netns-scoped
	// sysctl and bwrap's --disable-userns.
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")

	if err := bringLoopbackUp(); err != nil {
		fmt.Fprintf(os.Stderr, "keg netns stage: loopback: %v\n", err)
		os.Exit(125)
	}
	if err := allowLowPorts(); err != nil {
		fmt.Fprintf(os.Stderr, "keg netns stage: port floor: %v\n", err)
		os.Exit(125)
	}
	// All privileged setup is done; bwrap refuses unexpected capabilities,
	// and the sandbox does not need them.
	// Channel ends arrive at fds 3..6 (parent's ExtraFiles). Wrap each fd
	// exactly once — every consumer shares these handles so the poller sees
	// a single registration per descriptor.
	channelFiles := make([]*os.File, FDPreserved)
	for i, fd := range []int{FDProxy, FDDNS, FDRunner, FDPorts} {
		channelFiles[i] = os.NewFile(uintptr(fd), fmt.Sprintf("channel-%d", i))
	}

	if cfg.Transparent {
		if err := setupTransparentNet(cfg.OutboundIP, cfg.TransparentPorts); err != nil {
			fmt.Fprintf(os.Stderr, "keg netns stage: transparent: %v\n", err)
			os.Exit(125)
		}
		if err := startTransparentRelay(channelFiles[0]); err != nil {
			fmt.Fprintf(os.Stderr, "keg netns stage: transparent relay: %v\n", err)
			os.Exit(125)
		}
	}

	if cfg.DNS != nil {
		if err := startDNSRelay(channelFiles[FDDNS-FDProxy]); err != nil {
			fmt.Fprintf(os.Stderr, "keg netns stage: dns: %v\n", err)
			os.Exit(125)
		}
	}

	if err := dropCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "keg netns stage: drop caps: %v\n", err)
		os.Exit(125)
	}

	cmd := exec.CommandContext(context.Background(), cfg.BwrapPath, cfg.Args...) // #nosec G702 -- args built by BuildArgs from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = channelFiles
	err := cmd.Run()
	code := exitCodeOf(err)
	os.Exit(code)
}

// startDNSRelay exposes the filtering resolver on loopback UDP+TCP :53 of
// the wrapper namespace. Queries travel framed over the fd4 channel to the
// host side, where policy (hosts → whitelist → upstream) runs with real
// network reachability — the private namespace itself has no routes.
func startDNSRelay(file *os.File) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		return fmt.Errorf("bind udp :53: %w", err)
	}
	tcpLn, lerr := lc.Listen(context.Background(), "tcp", "127.0.0.1:53")
	if lerr != nil {
		_ = pc.Close()
		return fmt.Errorf("bind tcp :53: %w", lerr)
	}
	sess := muxado.Client(file, nil)
	bridge := dns.NewBridge(sess, pc.(*net.UDPConn), tcpLn)
	go func() { _ = bridge.Serve() }()
	return nil
}

// --- privileged network setup (pure syscalls, no external tools) ---------

// bringLoopbackUp raises the lo interface via SIOCSIFFLAGS.
func bringLoopbackUp() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer func() { _ = syscall.Close(s) }()
	var ifr ifreqFlags
	copy(ifr.name[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)) /* #nosec G103 -- kernel ifreq ioctl contract */); errno != 0 {
		return fmt.Errorf("get flags: %w", errno)
	}
	ifr.flags |= syscall.IFF_UP
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)) /* #nosec G103 -- kernel ifreq ioctl contract */); errno != 0 {
		return fmt.Errorf("set flags: %w", errno)
	}
	return nil
}

// allowLowPorts attempts to lower ip_unprivileged_port_start inside the private
// network namespace. Per-netns scope: no effect on the host. If /proc/sys is
// mounted read-only (common in container/k8s environments) or write access is
// restricted, the error is ignored because the netns stage retains
// CAP_NET_BIND_SERVICE to bind low ports (e.g. :53) before dropping capabilities,
// and clients reaching low ports do not require capabilities.
func allowLowPorts() error {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_unprivileged_port_start",
		[]byte("0"), 0o600) // #nosec G304 -- fixed kernel path
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("write sysctl: %w", err)
}

// dropCapabilities clears effective/permitted/inheritable sets entirely so
// bubblewrap accepts its own unprivileged path.
func dropCapabilities() error {
	hdr := capHeader{version: capVersion1, pid: 0}
	var data [2]capData
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)) /* #nosec G103 -- kernel capset contract */, uintptr(unsafe.Pointer(&data[0])) /* #nosec G103 */, 0); errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}
	return nil
}

// exitCodeOf maps an exec result onto a process exit code (child code
// verbatim, signal death as 128+signum, other errors 127).
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !exitErrorAs(err, &ee) {
		return 127
	}
	if code := ee.ExitCode(); code >= 0 {
		return code
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 127
	}
	return 128 + int(ws.Signal())
}

// keep muxado import referenced until channel A moves fully behind the
// stage (proxy bridge still uses it on the host side).
var _ = muxado.Client
