package orchestrator

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestParseBwrapVersionString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		output  string
		wantVer BwrapVersion
		wantErr string
	}{
		{
			name:    "standard version",
			output:  "bubblewrap 0.11.0\n",
			wantVer: BwrapVersion{Major: 0, Minor: 11, Patch: 0},
		},
		{
			name:    "major minor only",
			output:  "bubblewrap 0.8\n",
			wantVer: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
		},
		{
			name:    "future version",
			output:  "bubblewrap 1.2.3\n",
			wantVer: BwrapVersion{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:    "garbage output",
			output:  "not-a-version\n",
			wantErr: "cannot parse",
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: "cannot parse",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ver, err := ParseBwrapVersionString(tc.output)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				if ver != tc.wantVer {
					t.Fatalf("got version %+v, want %+v", ver, tc.wantVer)
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

func TestCheckBwrapCompatibility(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version BwrapVersion
		plan    Plan
		wantErr string
	}{
		{
			name:    "bwrap 0.11 with overlay is compatible",
			version: BwrapVersion{Major: 0, Minor: 11, Patch: 0},
			plan:    Plan{Overlay: OverlayEphemeral},
		},
		{
			name:    "bwrap 0.11 with seccomp on is compatible",
			version: BwrapVersion{Major: 0, Minor: 11, Patch: 0},
			plan:    Plan{Seccomp: "on"},
		},
		{
			name:    "bwrap 0.8 with plain overlay and seccomp auto is compatible",
			version: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
			plan:    Plan{Overlay: OverlayPlain, Seccomp: "auto"},
		},
		{
			name:    "bwrap 0.8 with plain overlay and seccomp off is compatible",
			version: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
			plan:    Plan{Overlay: OverlayPlain, Seccomp: "off"},
		},
		{
			name:    "bwrap 0.8 with ephemeral overlay is rejected",
			version: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
			plan:    Plan{Overlay: OverlayEphemeral},
			wantErr: "overlay mounts",
		},
		{
			name:    "bwrap 0.8 with disk overlay is rejected",
			version: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
			plan:    Plan{Overlay: OverlayDisk},
			wantErr: "overlay mounts",
		},
		{
			name:    "bwrap 0.8 with explicit seccomp on is rejected",
			version: BwrapVersion{Major: 0, Minor: 8, Patch: 0},
			plan:    Plan{Seccomp: "on"},
			wantErr: "seccomp filter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkBwrapCompatibilityParsed(tc.version, tc.plan)
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

// TestCheckBwrapVersion table-drives the basic version enforcement logic.
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
			name:    "old version rejected by generic >= 0.11 check",
			output:  "bubblewrap 0.8.0\n",
			wantErr: "bwrap >= 0.11",
		},
		{
			name:    "ancient version rejected by generic >= 0.11 check",
			output:  "bubblewrap 0.4.1\n",
			wantErr: "bwrap >= 0.11",
		},
		{
			name:    "garbage output rejected",
			output:  "not-a-version\n",
			wantErr: "cannot parse",
		},
		{name: "empty output rejected", output: "", wantErr: "cannot parse"},
		{
			name:    "missing binary rejected",
			execErr: true,
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
	ctx := context.Background()
	ver, err := GetBwrapVersion(ctx, "bwrap")
	if err != nil {
		t.Fatalf("GetBwrapVersion on installed bwrap failed: %v", err)
	}
	if ver.Major == 0 && ver.Minor < 11 {
		t.Logf("installed bwrap %d.%d.%d is older than 0.11", ver.Major, ver.Minor, ver.Patch)
	}
}
