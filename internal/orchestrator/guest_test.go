package orchestrator

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

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
