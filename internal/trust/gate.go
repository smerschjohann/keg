package trust

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// IsTerminal reports whether v (typically an *os.File or io.Reader) is connected to a terminal.
func IsTerminal(v any) bool {
	if f, ok := v.(*os.File); ok {
		_, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
		return err == nil
	}
	return false
}

// EnsureTrust checks if the repository configuration at cfgPath is approved in store.
// If the file is missing or empty, it returns approved=true.
// If untrusted:
//   - NoteCurrent is called to record CurrentSHA and timestamp.
//   - In TTY mode, a diff and checksum are printed to stdout, prompting the user for approval.
//   - In non-TTY mode, it returns approved=false with a descriptive error directing the user to 'keg trust'.
func EnsureTrust(
	ctx context.Context,
	store *Store,
	repoPath string,
	cfgPath string,
	stdin io.Reader,
	stdout io.Writer,
	isTerm func(any) bool,
) (bool, error) {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if isTerm == nil {
		isTerm = IsTerminal
	}

	data, err := os.ReadFile(cfgPath) // #nosec G304 -- config resolution
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("read repo config %s: %w", cfgPath, err)
	}
	if len(data) == 0 {
		return true, nil
	}

	sha, err := Sha256(data)
	if err != nil {
		return false, err
	}

	key := CleanRepoKey(repoPath)
	if store.Repos == nil {
		store.Repos = make(map[string]Entry)
	}
	entry, exists := store.Repos[key]

	if exists && IsTrusted(entry, sha) {
		return true, nil
	}

	// Record the current state unconditionally
	if _, err := NoteCurrent(store, repoPath, data); err != nil {
		return false, fmt.Errorf("note current config state: %w", err)
	}

	if !isTerm(stdin) {
		return false, fmt.Errorf("repository configuration at %s is untrusted or has changed (run 'keg trust' to approve)", cfgPath)
	}

	// Interactive TTY prompt
	diff := FormatDiff(entry.ApprovedContent, string(data), !exists || entry.ApprovedSHA == "")
	_, _ = fmt.Fprintf(stdout, "%s\n", diff)
	_, _ = fmt.Fprintf(stdout, "Checksum: %s\n", sha)
	_, _ = fmt.Fprint(stdout, "Trust this configuration? (yes/no): ")

	reader := bufio.NewReader(stdin)
	ans, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", readErr)
	}

	ans = strings.TrimSpace(strings.ToLower(ans))
	switch ans {
	case "ja", "j", "yes", "y":
		if _, approveErr := Approve(store, repoPath, data); approveErr != nil {
			return false, fmt.Errorf("approve config: %w", approveErr)
		}
		return true, nil
	default:
		return false, fmt.Errorf("repository configuration not approved for %s", repoPath)
	}
}

// EnsureTrustFile loads the trust store from trustStorePath, runs EnsureTrust,
// and saves the updated store back to disk.
func EnsureTrustFile(
	ctx context.Context,
	trustStorePath string,
	repoPath string,
	cfgPath string,
	stdin io.Reader,
	stdout io.Writer,
	isTerm func(any) bool,
) (bool, error) {
	resolvedTrustPath := Path(trustStorePath)
	store, err := LoadFile(resolvedTrustPath)
	if err != nil {
		return false, err
	}

	approved, trustErr := EnsureTrust(ctx, store, repoPath, cfgPath, stdin, stdout, isTerm)
	// Always persist updated store (NoteCurrent or Approve changes)
	if saveErr := SaveFile(resolvedTrustPath, store); saveErr != nil {
		if trustErr != nil {
			return false, errors.Join(trustErr, saveErr)
		}
		return false, saveErr
	}

	return approved, trustErr
}
