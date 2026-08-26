//go:build integration

package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/runner"
)

// TestMain routes guest invocations of THIS test binary into the sandbox
// entrypoint: Launch binds the running binary as /.keg/keg, so an
// integration test's sandbox executes this suite binary again — it must
// behave as the keg guest, never start the suite inside the sandbox.
func TestMain(m *testing.M) {
	if orchestrator.InitGuestDispatch() {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "delegate" {
		conn, err := runner.Dial()
		if err != nil {
			fmt.Fprintf(os.Stderr, "keg delegate: %v\n", err)
			os.Exit(runner.CodeNoRunner)
		}
		os.Exit(runner.Exec(conn, os.Args[2:], "", os.Stdout, os.Stderr))
	}
	dir, err := os.MkdirTemp("", "keg-integration-userconfig")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: create temp user config dir:", err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: set XDG_CONFIG_HOME:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
