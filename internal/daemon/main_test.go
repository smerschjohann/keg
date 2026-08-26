package daemon

import (
	"os"
	"testing"

	"github.com/smerschjohann/keg/internal/orchestrator"
)

func TestMain(m *testing.M) {
	if orchestrator.InitGuestDispatch() {
		return
	}
	os.Exit(m.Run())
}
