package orchestrator

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Minimum required bubblewrap version: 0.11 introduced --overlay-src and
// --add-seccomp-fd, both required by keg (WP-M8b enforces the check at
// startup so an incompatible bwrap fails as exit-127-class runner error
// instead of a misleading mount failure inside the sandbox).
const (
	bwrapMinMajor = 0
	bwrapMinMinor = 11
)

// bwrapInstallHints lists per-distro commands shown on version mismatch.
// Ordered output is produced by the slice, the map key is documentation.
var bwrapInstallHints = []string{
	"Fedora 40+ / Debian trixie-sid: install the bubblewrap package",
	"Debian 12 bookworm ships 0.8.0 which is too old — use a newer release",
	"older distros: static build from https://github.com/containers/bubblewrap " +
		"(needs libseccomp for --add-seccomp-fd)",
}

var (
	bwrapVersionMu sync.Mutex
	// bwrapVersionCache memoizes results per binary path: the check runs on
	// every sandbox launch and the binary cannot meaningfully change mid-
	// session. Errors are cached as well (fail-fast stays fail-fast).
	bwrapVersionCache = map[string]error{}
)

// CheckBwrapVersion verifies that the bwrap binary at path is >= 0.11.
// path may be a plain name resolved through PATH.
func CheckBwrapVersion(path string) error {
	bwrapVersionMu.Lock()
	if err, ok := bwrapVersionCache[path]; ok {
		bwrapVersionMu.Unlock()
		return err
	}
	bwrapVersionMu.Unlock()

	err := checkBwrapVersionExec(path)

	bwrapVersionMu.Lock()
	bwrapVersionCache[path] = err
	bwrapVersionMu.Unlock()
	return err
}

// checkBwrapVersionExec runs `bwrap --version` and parses its output.
func checkBwrapVersionExec(path string) error {
	out, err := exec.Command(path, "--version").Output() // #nosec G204 -- trusted binary path from config/LookPath
	if err != nil {
		return checkBwrapVersionParsed("", true)
	}
	return checkBwrapVersionParsed(string(out), false)
}

// checkBwrapVersionParsed is the pure core: it maps the (simulated) output
// of `bwrap --version` plus an exec-failure flag to an error. Table-driven
// tests exercise this without running bwrap (WP-M8b test 2).
func checkBwrapVersionParsed(output string, execErr bool) error {
	if execErr {
		return fmt.Errorf("bwrap not found or not executable")
	}
	trimmed := strings.TrimSpace(output)
	var major, minor, patch int
	// "bubblewrap 0.11.0" — the patch component is read defensively; some
	// distro builds print only major.minor.
	n, scanErr := fmt.Sscanf(trimmed, "bubblewrap %d.%d.%d", &major, &minor, &patch)
	if scanErr != nil && n < 2 {
		return fmt.Errorf("cannot parse bwrap version from %q", trimmed)
	}
	if major > bwrapMinMajor || (major == bwrapMinMajor && minor >= bwrapMinMinor) {
		return nil
	}
	return fmt.Errorf("bwrap >= %d.%d required, got %q — install hints: %s",
		bwrapMinMajor, bwrapMinMinor, trimmed, strings.Join(bwrapInstallHints, "; "))
}
