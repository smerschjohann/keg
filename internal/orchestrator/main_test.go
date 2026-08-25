package orchestrator

import (
	"os"
	"testing"

	"github.com/moby/sys/reexec"
)

// TestMain dispatches reentrant reexec invocations: under `go test` the
// re-executed process is this test binary, so guest dispatch must happen
// here before the regular test runner starts.
func TestMain(m *testing.M) {
	if reexec.Init() {
		return
	}
	os.Exit(m.Run())
}
