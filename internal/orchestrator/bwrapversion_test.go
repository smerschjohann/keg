package orchestrator

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCheckBwrapVersion table-drives the parser/enforcement logic
// (WP-M8b step 2, red phase).
func TestCheckBwrapVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		output  string // simulated `bwrap --version` stdout
		execErr bool   // bwrap binary missing / not executable
		wantErr string // empty => expect success; otherwise substring match
	}{
		{name: "current version accepted", output: "bubblewrap 0.11.0\n"},
		{name: "newer version accepted", output: "bubblewrap 0.12.1\n"},
		{name: "future major accepted", output: "bubblewrap 1.0.0\n"},
		{
			name: "old version rejected", output: "bubblewrap 0.8.0\n",
			wantErr: "bwrap >= 0.11",
		},
		{
			name: "ancient version rejected", output: "bubblewrap 0.4.1\n",
			wantErr: "bwrap >= 0.11",
		},
		{
			name: "garbage output rejected", output: "not-a-version\n",
			wantErr: "cannot parse",
		},
		{name: "empty output rejected", output: "", wantErr: "cannot parse"},
		{
			name: "missing binary rejected", execErr: true,
			wantErr: "bwrap not found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkBwrapVersionParsed(tc.output, tc.execErr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestCheckBwrapVersion_RealBinary exercises the exec path against the
// bwrap found in PATH (skipped visibly when absent — WP test rules).
func TestCheckBwrapVersion_RealBinary(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not in PATH — skipping real-binary version check")
	}
	if err := CheckBwrapVersion("bwrap"); err != nil {
		t.Fatalf("installed bwrap >= 0.11 rejected: %v", err)
	}
}
