package orchestrator

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.ngrok.com/muxado"

	"github.com/moby/sys/reexec"
)

// TestGuest_ExecsCommand verifies the reexec entrypoint transparently
// execs the given command.
func TestGuest_ExecsCommand(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c", "printf hello-guest")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v; output: %s", err, out.String())
	}
	if strings.TrimSpace(out.String()) != "hello-guest" {
		t.Errorf("guest output = %q, want hello-guest", out.String())
	}
}

// TestInvariant_GuestStripsHostEnv proves that even when bwrap-side
// stripping were bypassed, the guest itself never lets proxy/cloud
// credentials through to the workload (THREAT_MODEL.md §8.2).
func TestInvariant_GuestStripsHostEnv(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c", `printf "%s" "$HTTP_PROXY,$AWS_SESSION_TOKEN,$OPENAI_API_KEY"`)

	// Pass host-like environment including credentials.
	env := os.Environ()
	env = append(env,
		"HTTP_PROXY=http://corp-proxy:3128",
		"AWS_SESSION_TOKEN=super-secret",
		"OPENAI_API_KEY=sk-leak",
		"GUEST_ALLOWED=yes",
	)
	cmd.Env = env

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v; output: %s", err, out.String())
	}
	got := out.String()
	if got != ",," {
		t.Errorf("host credentials leaked into sandbox process: %q", got)
	}
}

func TestGuest_PreservesExplicitEnv(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c", `printf "%s" "$GUEST_ALLOWED,$HOME"`)
	env := append(os.Environ(), "GUEST_ALLOWED=yes", "HOME=/home/sandbox")
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v", err)
	}
	if out.String() != "yes,/home/sandbox" {
		t.Errorf("explicit env lost: %q", out.String())
	}
}

// Compile-time guard: reexec.Init must be called from an init path so the
// child recognizes GuestCommandName.
func TestGuestRegisteredWithReexec(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("reexec registration missing or broken: %v", err)
	}
	_ = exec.Command // keep exec import if assertions change
}

func TestRunGuestCommand_ExitCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		argv []string
		want int
	}{
		{
			name: "success exits zero",
			argv: []string{"/bin/sh", "-c", "exit 0"},
			want: 0,
		},
		{
			name: "child exit code is mirrored",
			argv: []string{"/bin/sh", "-c", "exit 3"},
			want: 3,
		},
		{
			name: "missing binary yields 127",
			argv: []string{"/nonexistent-binary-xyz"},
			want: 127,
		},
		{
			name: "signal death maps to 128+signum",
			argv: []string{"/bin/sh", "-c", "kill -TERM $$"},
			want: 143,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := runGuestCommand(tt.argv); got != tt.want {
				t.Fatalf("runGuestCommand(%v) = %d, want %d", tt.argv, got, tt.want)
			}
		})
	}
}

// TestRunGuestCommand_SignalForwarding pins that SIGTERM sent to the guest
// reaches the child instead of killing only the resident wrapper.
func TestRunGuestCommand_SignalForwarding(t *testing.T) {
	got := make(chan int, 1)
	go func() { got <- runGuestCommand([]string{"/bin/sleep", "60"}) }()
	time.Sleep(200 * time.Millisecond) // let the child start
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("self-signal: %v", err)
	}
	select {
	case code := <-got:
		if code == 0 {
			t.Fatal("sleep exited 0 despite SIGTERM")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runGuestCommand did not return after SIGTERM")
	}
}

// TestStartProxyBridge verifies that the guest bridge listens on the given
// loopback address and relays bytes onto the proxy channel session.
func TestStartProxyBridge(t *testing.T) {
	hostEnd, guestEnd, err := Socketpair()
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer hostEnd.Close()

	serverSess := muxado.Server(hostEnd, nil)
	defer serverSess.Close() // #nosec G307 -- test cleanup

	peerPayload := make(chan string, 1)
	go func() {
		stream, err := serverSess.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 512)
		n, _ := stream.Read(buf)
		peerPayload <- string(buf[:n])
	}()

	ln, err := listenLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	bridge, clientSess := startProxyBridge(guestEnd, ln)
	go func() { _ = bridge.Serve() }()
	defer func() {
		// Order matters: session close wakes all pipe goroutines; only
		// then can bridge.Close finish its in-flight wait.
		_ = clientSess.Close()
		_ = serverSess.Close()
		_ = bridge.Close()
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	payload := "CONNECT proxy.golang.org:443 HTTP/1.1\r\n\r\n"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	_, _ = conn.Read(buf) // response not needed; peer receipt is the assertion

	select {
	case got := <-peerPayload:
		if !strings.Contains(got, "CONNECT proxy.golang.org:443") {
			t.Fatalf("peer received wrong payload: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("payload never reached the host-side session")
	}
}
