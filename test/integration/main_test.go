//go:build integration

package integration

import (
	"os"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

// TestMain routes guest invocations of THIS test binary into the sandbox
// entrypoint: Launch binds the running binary as /.keg/keg, so an
// integration test's sandbox executes this suite binary again — it must
// behave as the keg guest, never start the suite inside the sandbox.
func TestMain(m *testing.M) {
	if orchestrator.InitGuestDispatch() {
		return
	}
	os.Exit(m.Run())
}
