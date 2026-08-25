package orchestrator

import (
	"fmt"
	"os"
	"slices"
	"syscall"
)

// Socketpair returns the two ends of an AF_UNIX SOCK_STREAM socketpair as
// os.Files, ready to be handed to a child process via cmd.ExtraFiles.
// Ownership: both ends belong to the caller; each must be Closed exactly
// once (host ends by the Sandbox handle, guest ends after exec inheritance).
func Socketpair() (host, guest *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	host = os.NewFile(uintptr(fds[0]), "keg-socketpair-host")
	guest = os.NewFile(uintptr(fds[1]), "keg-socketpair-guest")
	return host, guest, nil
}

// StripDeniedEnv filters an environment list (NAME=value entries), removing
// every variable whose name is in denied. Pure function; used as
// defense-in-depth on the guest side in addition to bwrap --unsetenv.
func StripDeniedEnv(env []string, denied []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		name, _, _ := cutEnvEntry(e)
		if slices.Contains(denied, name) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func cutEnvEntry(e string) (name, value string, ok bool) {
	for i := 0; i < len(e); i++ {
		if e[i] == '=' {
			return e[:i], e[i+1:], true
		}
	}
	return e, "", false
}
