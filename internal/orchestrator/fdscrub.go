package orchestrator

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// listOpenFDs returns the descriptor numbers currently open in this
// process, read from /proc/self/fd.
func listOpenFDs() ([]int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, fmt.Errorf("read /proc/self/fd: %w", err)
	}
	fds := make([]int, 0, len(entries))
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a numeric entry
		}
		fds = append(fds, n)
	}
	return fds, nil
}

// ScrubForeignFDs marks every open descriptor above stdio that is not in
// keep as close-on-exec. This prevents host-side fd leaks from crossing
// into the sandbox: bwrap intentionally passes unknown descriptors through
// to the child ("Any other fds will be passed on to the child though",
// bubblewrap.c), so keg must scrub before exec itself.
//
// Marking FD_CLOEXEC (instead of closing) keeps the descriptors usable by
// this process — only their inheritance is cut. Idempotent.
func ScrubForeignFDs(keep map[int]bool) error {
	fds, err := listOpenFDs()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		if fd <= 2 || keep[fd] {
			continue
		}
		syscall.CloseOnExec(fd)
	}
	return nil
}

// CloseAllFDsExcept closes every descriptor not listed. Used by the sandbox
// entrypoint as a second line of defense after the host-side CLOEXEC scrub;
// must be called before any subsystem opens descriptors the workload needs.
func CloseAllFDsExcept(keep ...int) error {
	keepSet := map[int]bool{0: true, 1: true, 2: true}
	for _, k := range keep {
		keepSet[k] = true
	}
	fds, err := listOpenFDs()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		if keepSet[fd] {
			continue
		}
		if err := syscall.Close(fd); err != nil && !errors.Is(err, syscall.EBADF) {
			return fmt.Errorf("close fd %d: %w", fd, err)
		}
	}
	return nil
}
