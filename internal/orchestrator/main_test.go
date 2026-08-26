package orchestrator

import (
	"os"
	"testing"
)

// TestMain dispatches reentrant reexec invocations: under `go test` the
// re-executed process is this test binary, so guest dispatch must happen
// here before the regular test runner starts.
func TestMain(m *testing.M) {
	// Full guest dispatch (both entrypoint shapes): when the test binary is
	// bound into a sandbox as the keg guest, it must behave like the
	// real CLI binary, not run the suite inside the sandbox.
	if InitGuestDispatch() {
		return
	}
	os.Exit(m.Run())
}
