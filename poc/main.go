// keg-poc — minimal proof of concept for the socketpair tunnel through
// bwrap.
//
// One binary, two roles (switched via env var, no reexec needed):
//
//	HOST:   creates two unix socketpairs, starts itself via bwrap
//	        --unshare-all and passes the sandbox ends as FD 3 + FD 4.
//	GUEST:  runs inside the sandbox network namespace (loopback only):
//	          FD 3 = echo channel     (raw tunnel)
//	          FD 4 = TCP tunnel       (channel-E pattern: host -> sandbox loopback)
//
// What is demonstrated:
//
//	Phase 1: host writes into its socketpair end -> guest echoes back.
//	         => communication crosses the isolation boundary.
//	Phase 2: host connects to 127.0.0.1:18080 (host-side listener),
//	         traffic is tunneled over FD 4 into the sandbox and answered
//	         by an HTTP server on 127.0.0.1:8080 there.
//	         => the "inner" socket is reachable from the outside.
//	Negative proof: the sandbox has no external network — outbound dials
//	         fail while the tunnel works.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	guestHTTPPort    = "8080"  // HTTP server INSIDE the sandbox
	hostForwardPort  = "18080" // listener ON THE HOST (channel E)
	guestReadyMarker = "KEG_POC_READY\n"
)

func main() {
	if os.Getenv("KEG_POC_GUEST") == "1" {
		guest()
		return
	}
	host()
}

// ---------------------------------------------------------------- HOST ----

func host() {
	fmt.Println("=== keg PoC: socketpair tunnel through bwrap ===")

	if _, err := exec.LookPath("bwrap"); err != nil {
		fatal("bwrap not found")
	}
	exe, err := os.Executable()
	if err != nil {
		fatal("cannot resolve executable: %v", err)
	}
	exeDir := filepath.Dir(exe)

	// Two socketpairs: [0]=host end, [1]=sandbox end (becomes FD 3 resp. 4)
	echoPair := mustSocketpair("echo")
	tunPair := mustSocketpair("tunnel")

	cmd := exec.Command("bwrap",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", exeDir, exeDir, // keep our own binary reachable
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--unshare-all", // PID/IPC/NET/UTS/User/Cgroup — full isolation
		"--die-with-parent",
		exe,
	)
	cmd.Env = append(os.Environ(), "KEG_POC_GUEST=1")
	cmd.ExtraFiles = []*os.File{echoPair[1], tunPair[1]} // -> FD 3, FD 4
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("[host] starting bwrap --unshare-all ...")
	if err := cmd.Start(); err != nil {
		fatal("failed to start bwrap: %v", err)
	}
	echoPair[1].Close() // close child ends in the parent
	tunPair[1].Close()
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	echo := echoPair[0]
	tun := tunPair[0]

	// Wait for guest readiness (first line over the echo channel)
	reader := bufio.NewReader(echo)
	line, err := reader.ReadString('\n')
	if err != nil || line != guestReadyMarker {
		fatal("guest not ready (got %q, err=%v)", line, err)
	}
	fmt.Println("[host] guest reported ready (via FD-3 channel): READY")

	// ---- Phase 1: echo over the raw tunnel ----
	fmt.Println("\n--- Phase 1: echo over unix socketpair (FD 3) ---")
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("hello from the host #%d", i)
		start := time.Now()
		if _, err := fmt.Fprintln(echo, msg); err != nil {
			fatal("send failed: %v", err)
		}
		reply, err := reader.ReadString('\n')
		if err != nil {
			fatal("no echo: %v", err)
		}
		fmt.Printf("[host] sent: %-32q received: %-32q (%v)\n",
			msg, trimNL(reply), time.Since(start).Round(time.Microsecond))
	}
	fmt.Println("✓ Tunnel established: host <-> sandbox communicate over FD 3.")

	// ---- Phase 2: TCP reach-through to the inner loopback ----
	fmt.Printf("\n--- Phase 2: tunnel to sandbox-%s (channel-E pattern, FD 4) ---\n", guestHTTPPort)

	ln, err := net.Listen("tcp", "127.0.0.1:"+hostForwardPort)
	if err != nil {
		fatal("host listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			// PoC: one connection at a time; production code would open a
			// muxado stream per connection instead.
			go pipeThrough(tun, client)
		}
	}()

	url := fmt.Sprintf("http://127.0.0.1:%s/", hostForwardPort)
	fmt.Printf("[host] GET %s ...\n", url)
	resp, err := http.Get(url) //nolint:noctx — PoC
	if err != nil {
		fatal("HTTP through the tunnel failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("[host] HTTP %d, body: %q\n", resp.StatusCode, trimNL(string(body)))
	if resp.StatusCode == 200 && len(body) > 0 {
		fmt.Println("✓ The inner sandbox socket was reached from outside:")
		fmt.Printf("  host :%s  --FD4-->  sandbox 127.0.0.1:%s (HTTP)\n",
			hostForwardPort, guestHTTPPort)
	}

	// ---- Negative proof: no external network in the sandbox ----
	fmt.Println("\n--- Negative proof: external network of the sandbox ---")
	if _, err := fmt.Fprintln(echo, "PROBE_NET"); err != nil {
		fatal("send failed: %v", err)
	}
	result, err := reader.ReadString('\n')
	if err != nil {
		fatal("no answer: %v", err)
	}
	fmt.Printf("[host] guest reports: %s", result)

	fmt.Println("\n=== PoC passed ===")
}

// pipeThrough connects a host TCP client 1:1 to the tunnel FD; the guest
// dials the target on its own loopback.
func pipeThrough(tun io.ReadWriteCloser, client net.Conn) {
	defer client.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(tun, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, tun); done <- struct{}{} }()
	<-done
}

// ---------------------------------------------------------------- GUEST ---

func guest() {
	echoConn := fileConn(3, "echo")
	tunConn := fileConn(4, "tunnel")

	uid := os.Getuid()
	fmt.Printf("[guest] running in the sandbox (uid=%d). Starting services ...\n", uid)

	// HTTP server on the (isolated) sandbox loopback
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "Hello from the HTTP server INSIDE the sandbox (pid %d)\n", os.Getpid())
	})
	ln, err := net.Listen("tcp", "127.0.0.1:"+guestHTTPPort)
	if err != nil {
		guestFatal(err)
	}
	go func() { _ = http.Serve(ln, mux) }()

	// Echo server over FD 3 + readiness signal to the host
	go func() {
		r := bufio.NewReader(echoConn)
		if _, err := fmt.Fprint(echoConn, guestReadyMarker); err != nil {
			guestFatal(err)
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch trimNL(line) {
			case "PROBE_NET":
				// Negative probe: external network must be blocked
				conn, derr := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
				if derr != nil {
					fmt.Fprintf(echoConn,
						"dial 1.1.1.1:80 blocked ✓ (%v) — isolation active\n", derr)
				} else {
					conn.Close()
					fmt.Fprintln(echoConn, "WARNING: outbound dial SUCCEEDED — isolation compromised!")
				}
			default:
				fmt.Fprintf(echoConn, "echo: %s", line) // 1:1 back
			}
		}
	}()

	// Tunnel server over FD 4: dials the target on its own loopback.
	// PoC: sequential, one connection at a time.
	for {
		c, err := net.Dial("tcp", "127.0.0.1:"+guestHTTPPort)
		if err != nil {
			guestFatal(err)
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(tunConn, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, tunConn); done <- struct{}{} }()
		<-done
		c.Close()
	}
}

// -------------------------------------------------------------- HELPERS ---

// mustSocketpair creates an AF_UNIX SOCK_STREAM pair (the pwpeer pattern).
func mustSocketpair(name string) [2]*os.File {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fatal("socketpair (%s): %v", name, err)
	}
	a := os.NewFile(uintptr(fds[0]), name+"-host")
	b := os.NewFile(uintptr(fds[1]), name+"-sandbox")
	return [2]*os.File{a, b}
}

func fileConn(fd int, name string) net.Conn {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		guestFatal(fmt.Errorf("FD %d (%s) not present", fd, name))
	}
	c, err := net.FileConn(f)
	if err != nil {
		guestFatal(err)
	}
	return c
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[host] ✗ "+format+"\n", args...)
	os.Exit(1)
}

func guestFatal(err error) {
	fmt.Fprintf(os.Stderr, "[guest] ✗ %v\n", err)
	os.Exit(1)
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
