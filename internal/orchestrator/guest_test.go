package orchestrator

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/landlock"

	"github.com/moby/sys/reexec"
	"golang.ngrok.com/muxado"
)

// TestGuestCommandNames verifies that internal reexec / entrypoint command
// names are short and clean rather than full module paths.
func TestGuestCommandNames(t *testing.T) {
	if GuestCommandName != "guest" {
		t.Errorf("GuestCommandName = %q, want %q", GuestCommandName, "guest")
	}
	if NetnsStageCommandName != "netns-stage" {
		t.Errorf("NetnsStageCommandName = %q, want %q", NetnsStageCommandName, "netns-stage")
	}
}

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

// TestGuest_ReappliesProxyEnv proves the guest derives its proxy variables
// from the KEG_PROXY marker AFTER stripping host credentials: injected
// egress config survives hygiene while host proxies never do.
func TestGuest_ReappliesProxyEnv(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c",
		`printf "%s|%s" "$HTTP_PROXY" "$NO_PROXY"`)
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY=http://host-leak:9999", // must NOT survive
		EnvProxyBridge+"=127.0.0.1:18081",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v; %s", err, out.String())
	}
	got := out.String()
	if got != "http://127.0.0.1:18081|localhost,127.0.0.1" {
		t.Errorf("guest proxy env = %q", got)
	}
}

func TestBuildKeepEnv(t *testing.T) {
	tests := []struct {
		name     string
		marker   string
		environ  []string
		wantSet  map[string]string
		dontWant []string
	}{
		{
			name: "inherit specific vars and set overrides",
			marker: `{
				"core": ["HOME", "PATH"],
				"inherit": ["KEEP_VAR", "OVERRIDE_VAR"],
				"set": {"OVERRIDE_VAR": "new_val", "EXPLICIT_VAR": "set_val"},
				"all": false
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"PATH=/usr/bin:/bin",
				"KEEP_VAR=keep_me",
				"OVERRIDE_VAR=old_val",
				"LEAK_VAR=leak",
				"AWS_SECRET_ACCESS_KEY=secret",
				"KEG_RUNNER=1",
			},
			wantSet: map[string]string{
				"HOME":         "/home/sandbox",
				"PATH":         "/usr/bin:/bin",
				"KEEP_VAR":     "keep_me",
				"OVERRIDE_VAR": "new_val",
				"EXPLICIT_VAR": "set_val",
			},
			dontWant: []string{"LEAK_VAR", "AWS_SECRET_ACCESS_KEY", "KEG_RUNNER"},
		},
		{
			name: "all mode with denied and internal marker strip",
			marker: `{
				"core": ["HOME"],
				"all": true
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"USER_VAR=hello",
				"KEG_PORT_8080=8080",
				"CODE_KEG=1",
				"KEG_ENV_KEEP=marker",
				"KEG_RUNNER=1",
				"KEG_PORTS=8080",
				"KEG_LANDLOCK=auto",
				"HTTP_PROXY=http://leak",
				"AWS_SESSION_TOKEN=token",
			},
			wantSet: map[string]string{
				"HOME":          "/home/sandbox",
				"USER_VAR":      "hello",
				"KEG_PORT_8080": "8080",
				"CODE_KEG":      "1",
			},
			dontWant: []string{
				"KEG_ENV_KEEP", "KEG_RUNNER", "KEG_PORTS", "KEG_LANDLOCK",
				"HTTP_PROXY", "AWS_SESSION_TOKEN",
			},
		},
		{
			name: "proxy bridge env derived correctly",
			marker: `{
				"core": ["HOME"]
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"KEG_PROXY=127.0.0.1:18081",
				"HTTP_PROXY=http://host-leak:9999",
			},
			wantSet: map[string]string{
				"HOME":       "/home/sandbox",
				"HTTP_PROXY": "http://127.0.0.1:18081",
				"NO_PROXY":   "localhost,127.0.0.1",
			},
			dontWant: []string{"KEG_PROXY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildKeepEnv([]byte(tt.marker), tt.environ)
			gotMap := make(map[string]string)
			for _, entry := range got {
				parts := strings.SplitN(entry, "=", 2)
				if len(parts) == 2 {
					gotMap[parts[0]] = parts[1]
				}
			}

			for k, wantVal := range tt.wantSet {
				if val, ok := gotMap[k]; !ok || val != wantVal {
					t.Errorf("gotMap[%s] = %q (exists=%v), want %q", k, val, ok, wantVal)
				}
			}

			for _, dont := range tt.dontWant {
				if _, ok := gotMap[dont]; ok {
					t.Errorf("gotMap should NOT contain %s, but got %q", dont, gotMap[dont])
				}
			}
		})
	}
}

func TestBuildKeepEnv_Interactive(t *testing.T) {
	tests := []struct {
		name        string
		marker      string
		environ     []string
		interactive bool
		wantSet     map[string]string
		dontWant    []string
	}{
		{
			name: "interactive forwards TERM, COLORTERM and LANG from environ",
			marker: `{
				"core": ["HOME"]
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"TERM=xterm-256color",
				"COLORTERM=truecolor",
				"LANG=en_US.UTF-8",
				"OTHER_LEAK=leak",
			},
			interactive: true,
			wantSet: map[string]string{
				"HOME":      "/home/sandbox",
				"TERM":      "xterm-256color",
				"COLORTERM": "truecolor",
				"LANG":      "en_US.UTF-8",
			},
			dontWant: []string{"OTHER_LEAK"},
		},
		{
			name: "interactive does not default TERM when unset in environ",
			marker: `{
				"core": ["HOME"]
			}`,
			environ: []string{
				"HOME=/home/sandbox",
			},
			interactive: true,
			wantSet: map[string]string{
				"HOME": "/home/sandbox",
			},
			dontWant: []string{"TERM"},
		},
		{
			name: "interactive respects unset for TERM and COLORTERM",
			marker: `{
				"core": ["HOME"],
				"unset": ["COLORTERM", "TERM"]
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"TERM=xterm-256color",
				"COLORTERM=truecolor",
			},
			interactive: true,
			wantSet: map[string]string{
				"HOME": "/home/sandbox",
			},
			dontWant: []string{"TERM", "COLORTERM"},
		},
		{
			name: "interactive set beats inherited TERM",
			marker: `{
				"core": ["HOME"],
				"set": {"TERM": "dumb"}
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"TERM=xterm-256color",
			},
			interactive: true,
			wantSet: map[string]string{
				"HOME": "/home/sandbox",
				"TERM": "dumb",
			},
		},
		{
			name: "non-interactive drops TERM and COLORTERM unless inherited",
			marker: `{
				"core": ["HOME"]
			}`,
			environ: []string{
				"HOME=/home/sandbox",
				"TERM=xterm-256color",
				"COLORTERM=truecolor",
			},
			interactive: false,
			wantSet: map[string]string{
				"HOME": "/home/sandbox",
			},
			dontWant: []string{"TERM", "COLORTERM"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildKeepEnvInteractive([]byte(tt.marker), tt.environ, tt.interactive)
			gotMap := make(map[string]string)
			for _, entry := range got {
				parts := strings.SplitN(entry, "=", 2)
				if len(parts) == 2 {
					gotMap[parts[0]] = parts[1]
				}
			}

			for k, wantVal := range tt.wantSet {
				if val, ok := gotMap[k]; !ok || val != wantVal {
					t.Errorf("gotMap[%s] = %q (exists=%v), want %q", k, val, ok, wantVal)
				}
			}

			for _, dont := range tt.dontWant {
				if _, ok := gotMap[dont]; ok {
					t.Errorf("gotMap should NOT contain %s, but got %q", dont, gotMap[dont])
				}
			}
		})
	}
}

func TestInvariant_WorkloadGetsOnlyExplicitEnv(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c",
		`printf "%s|%s|%s" "$HOST_LEAK" "$ALLOWED_VAR" "$SET_VAR"`)

	marker := `{
		"inherit": ["ALLOWED_VAR"],
		"set": {"SET_VAR": "custom"}
	}`
	cmd.Env = []string{
		"HOST_LEAK=leak_val",
		"ALLOWED_VAR=allowed_val",
		EnvKeepMarkerName + "=" + marker,
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v; %s", err, out.String())
	}
	got := out.String()
	if got != "|allowed_val|custom" {
		t.Errorf("workload received unexpected env: got %q, want '|allowed_val|custom'", got)
	}
}

func TestInvariant_InheritAllStillHidesDenied(t *testing.T) {
	cmd := reexec.Command(GuestCommandName, "/bin/sh", "-c",
		`printf "%s|%s|%s" "$HOST_VAR" "$AWS_SESSION_TOKEN" "$HTTPS_PROXY"`)

	marker := `{"all": true}`
	cmd.Env = []string{
		"HOST_VAR=survives",
		"AWS_SESSION_TOKEN=secret_token",
		"HTTPS_PROXY=http://corp-proxy",
		EnvKeepMarkerName + "=" + marker,
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("guest run: %v; %s", err, out.String())
	}
	got := out.String()
	if got != "survives||" {
		t.Errorf("inherit_all leaked denied variables: got %q, want 'survives||'", got)
	}
}

func TestBuildGuestLandlockConfig(t *testing.T) {
	cfg := buildGuestLandlockConfig(landlock.ModeAuto, "/home/sandbox", "/workspace", "/var/cache/custom", "/data/rw")
	if cfg.Mode != landlock.ModeAuto {
		t.Errorf("Mode = %v, want %v", cfg.Mode, landlock.ModeAuto)
	}
	if !slices.Contains(cfg.ReadOnlyDirs, "/") {
		t.Errorf("ReadOnlyDirs should contain '/', got %v", cfg.ReadOnlyDirs)
	}
	wantWritable := []string{"/tmp", "/dev", "/home/sandbox", "/workspace", "/var/cache/custom", "/data/rw"}
	for _, w := range wantWritable {
		if !slices.Contains(cfg.WritableDirs, w) {
			t.Errorf("WritableDirs should contain %q, got %v", w, cfg.WritableDirs)
		}
	}
}
