package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Minimum required bubblewrap version for advanced features (--overlay-src,
// --add-seccomp-fd).
const (
	bwrapMinMajor = 0
	bwrapMinMinor = 11
)

// BwrapVersion represents a parsed bubblewrap semver version.
type BwrapVersion struct {
	Major int
	Minor int
	Patch int
}

// bwrapInstallHints lists per-distro commands shown on version mismatch.
var bwrapInstallHints = []string{
	"Fedora 40+ / Debian trixie-sid: install the bubblewrap package",
	"Debian 12 bookworm ships 0.8.0 which is too old for overlay mounts and seccomp — use a newer release",
	"older distros: static build from https://github.com/containers/bubblewrap " +
		"(needs libseccomp for --add-seccomp-fd)",
}

var (
	bwrapVersionMu sync.Mutex
	// bwrapVersionCache memoizes parsed versions per binary path.
	bwrapVersionCache = map[string]cachedVersionResult{}
)

type cachedVersionResult struct {
	ver BwrapVersion
	err error
}

// ParseBwrapVersionString extracts major, minor and patch numbers from `bwrap --version` output.
func ParseBwrapVersionString(output string) (BwrapVersion, error) {
	trimmed := strings.TrimSpace(output)
	var major, minor, patch int
	// "bubblewrap 0.11.0" or "bubblewrap 0.8"
	n, scanErr := fmt.Sscanf(trimmed, "bubblewrap %d.%d.%d", &major, &minor, &patch)
	if scanErr != nil && n < 2 {
		return BwrapVersion{}, fmt.Errorf("cannot parse bwrap version from %q", trimmed)
	}
	return BwrapVersion{Major: major, Minor: minor, Patch: patch}, nil
}

// GetBwrapVersion inspects the bubblewrap binary at path and returns its parsed version.
func GetBwrapVersion(ctx context.Context, path string) (BwrapVersion, error) {
	bwrapVersionMu.Lock()
	if cached, ok := bwrapVersionCache[path]; ok {
		bwrapVersionMu.Unlock()
		return cached.ver, cached.err
	}
	bwrapVersionMu.Unlock()

	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, path, "--version") // #nosec G204 -- trusted binary path from config/LookPath
	out, err := cmd.Output()

	var ver BwrapVersion
	if err != nil {
		err = fmt.Errorf("bwrap not found or not executable: %w", err)
	} else {
		ver, err = ParseBwrapVersionString(string(out))
	}

	bwrapVersionMu.Lock()
	bwrapVersionCache[path] = cachedVersionResult{ver: ver, err: err}
	bwrapVersionMu.Unlock()

	return ver, err
}

// CheckBwrapCompatibility verifies whether the bubblewrap binary supports all
// features required by the given execution Plan. If a plan uses plain mounts
// and seccomp is not forced on, older bubblewrap versions are accepted.
func CheckBwrapCompatibility(ctx context.Context, path string, p Plan) error {
	ver, err := GetBwrapVersion(ctx, path)
	if err != nil {
		return err
	}
	return checkBwrapCompatibilityParsed(ver, p)
}

func checkBwrapCompatibilityParsed(ver BwrapVersion, p Plan) error {
	isNewEnough := ver.Major > bwrapMinMajor || (ver.Major == bwrapMinMajor && ver.Minor >= bwrapMinMinor)
	if isNewEnough {
		return nil
	}

	versionStr := fmt.Sprintf("bubblewrap %d.%d.%d", ver.Major, ver.Minor, ver.Patch)

	// Check if plan requires bwrap >= 0.11 features:
	// 1. Overlay mounts require --overlay-src (added in bwrap 0.11.0)
	if p.HasOverlay() {
		return fmt.Errorf("bwrap >= %d.%d required for overlay mounts (--overlay-src), got %q — install hints: %s",
			bwrapMinMajor, bwrapMinMinor, versionStr, strings.Join(bwrapInstallHints, "; "))
	}

	// 2. Explicitly requested seccomp enforcement requires --add-seccomp-fd (added in bwrap 0.11.0)
	if p.Seccomp == "on" {
		return fmt.Errorf("bwrap >= %d.%d required for seccomp filter (--add-seccomp-fd), got %q — install hints: %s",
			bwrapMinMajor, bwrapMinMinor, versionStr, strings.Join(bwrapInstallHints, "; "))
	}

	return nil
}

// CheckBwrapVersion verifies that the bwrap binary at path is >= 0.11.
// Maintained for direct call compatibility.
func CheckBwrapVersion(path string) error {
	ctx := context.Background()
	ver, err := GetBwrapVersion(ctx, path)
	if err != nil {
		return err
	}
	if ver.Major > bwrapMinMajor || (ver.Major == bwrapMinMajor && ver.Minor >= bwrapMinMinor) {
		return nil
	}
	versionStr := fmt.Sprintf("bubblewrap %d.%d.%d", ver.Major, ver.Minor, ver.Patch)
	return fmt.Errorf("bwrap >= %d.%d required, got %q — install hints: %s",
		bwrapMinMajor, bwrapMinMinor, versionStr, strings.Join(bwrapInstallHints, "; "))
}

func checkBwrapVersionParsed(output string, execErr bool) error {
	if execErr {
		return fmt.Errorf("bwrap not found or not executable")
	}
	ver, err := ParseBwrapVersionString(output)
	if err != nil {
		return err
	}
	if ver.Major > bwrapMinMajor || (ver.Major == bwrapMinMajor && ver.Minor >= bwrapMinMinor) {
		return nil
	}
	trimmed := strings.TrimSpace(output)
	return fmt.Errorf("bwrap >= %d.%d required, got %q — install hints: %s",
		bwrapMinMajor, bwrapMinMinor, trimmed, strings.Join(bwrapInstallHints, "; "))
}
