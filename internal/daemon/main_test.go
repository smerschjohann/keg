package daemon

import (
	"fmt"
	"os"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

func TestMain(m *testing.M) {
	if orchestrator.InitGuestDispatch() {
		return
	}
	// Never read the developer's real machine user config
	// (~/.config/keg/config.yaml): daemon tests that omit an explicit
	// user config expect defaults-only plans, independent of the host setup.
	dir, err := os.MkdirTemp("", "keg-test-userconfig")
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
