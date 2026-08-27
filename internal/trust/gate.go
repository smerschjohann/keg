package trust

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/smerschjohann/keg/internal/config"

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

// EnsureTrust checks if the repository configuration at cfgPath and all trust anchors are approved in store.
// If the file is missing or empty, it returns approved=true.
// If untrusted:
//   - NoteCurrent is called to record CurrentSHA and timestamp for config and all anchors.
//   - In TTY mode, diffs and checksums are printed to stdout, prompting the user for approval.
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

	repoCfg, _ := config.ParseRepo(data)
	anchors, _ := config.EffectiveTrustAnchors(repoCfg, repoPath)

	anchorContents := make(map[string][]byte)
	anchorSHAs := make(map[string]string)
	for _, relPath := range anchors {
		p := filepath.Join(repoPath, relPath)
		aBytes, aErr := os.ReadFile(p) // #nosec G304,G703 -- anchor file resolution
		if aErr != nil {
			if errors.Is(aErr, os.ErrNotExist) {
				continue
			}
			return false, fmt.Errorf("read trust anchor %s: %w", p, aErr)
		}
		if len(aBytes) > 0 {
			aSHA, shaErr := Sha256(aBytes)
			if shaErr != nil {
				return false, shaErr
			}
			anchorContents[relPath] = aBytes
			anchorSHAs[relPath] = aSHA
		}
	}

	key := CleanRepoKey(repoPath)
	if store.Repos == nil {
		store.Repos = make(map[string]Entry)
	}
	entry, exists := store.Repos[key]

	if exists && IsTrusted(entry, sha, anchorSHAs) {
		return true, nil
	}

	// Record the current state unconditionally
	if _, err := NoteCurrent(store, repoPath, data, anchorContents); err != nil {
		return false, fmt.Errorf("note current config state: %w", err)
	}

	if !isTerm(stdin) {
		return false, fmt.Errorf("repository configuration at %s is untrusted or has changed (run 'keg trust' to approve)", cfgPath)
	}

	// Interactive TTY prompt
	if !exists || entry.ApprovedSHA == "" || entry.ApprovedSHA != sha {
		diff := FormatDiff(entry.ApprovedContent, string(data), !exists || entry.ApprovedSHA == "")
		_, _ = fmt.Fprintf(stdout, "%s\n", diff)
	}
	for _, relPath := range anchors {
		aBytes, hasBytes := anchorContents[relPath]
		if !hasBytes {
			continue
		}
		aEntry := entry.Anchors[relPath]
		if aEntry.ApprovedSHA != anchorSHAs[relPath] {
			aDiff := FormatAnchorDiff(relPath, aEntry.ApprovedContent, string(aBytes), aEntry.ApprovedSHA == "")
			_, _ = fmt.Fprintf(stdout, "%s\n", aDiff)
		}
	}

	_, _ = fmt.Fprintf(stdout, "Checksum (.keg.yaml): %s\n", sha)
	for _, relPath := range anchors {
		if aSHA, ok := anchorSHAs[relPath]; ok {
			_, _ = fmt.Fprintf(stdout, "Checksum (%s): %s\n", relPath, aSHA)
		}
	}
	_, _ = fmt.Fprint(stdout, "Trust this configuration and trust anchors? (yes/no): ")

	reader := bufio.NewReader(stdin)
	ans, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", readErr)
	}

	ans = strings.TrimSpace(strings.ToLower(ans))
	switch ans {
	case "ja", "j", "yes", "y":
		if _, approveErr := Approve(store, repoPath, data, anchorContents); approveErr != nil {
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

// VerifyApproved checks if the current configuration and all trust anchors for repoPath
// match the approved records in the trust store at trustStorePath.
// If .keg.yaml does not exist or is empty, it returns nil.
func VerifyApproved(trustStorePath string, repoPath string, cfgPath string) error {
	data, err := os.ReadFile(cfgPath) // #nosec G304 -- config resolution
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config %s: %w", cfgPath, err)
	}
	if len(data) == 0 {
		return nil
	}

	cfgSHA, err := Sha256(data)
	if err != nil {
		return err
	}

	repoCfg, _ := config.ParseRepo(data)
	anchors, _ := config.EffectiveTrustAnchors(repoCfg, repoPath)

	anchorSHAs := make(map[string]string)
	for _, relPath := range anchors {
		p := filepath.Join(repoPath, relPath)
		aBytes, aErr := os.ReadFile(p) // #nosec G304,G703 -- anchor resolution
		if aErr != nil {
			if errors.Is(aErr, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("read trust anchor %s: %w", p, aErr)
		}
		if len(aBytes) > 0 {
			aSHA, shaErr := Sha256(aBytes)
			if shaErr != nil {
				return shaErr
			}
			anchorSHAs[relPath] = aSHA
		}
	}

	store, err := LoadFile(Path(trustStorePath))
	if err != nil {
		return err
	}

	key := CleanRepoKey(repoPath)
	entry, exists := store.Repos[key]
	if !exists || !IsTrusted(entry, cfgSHA, anchorSHAs) {
		return fmt.Errorf("repository configuration or trust anchor at %s is untrusted or modified", repoPath)
	}
	return nil
}
