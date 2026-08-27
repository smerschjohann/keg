package seccomp

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// CreateMemfd creates an in-memory anonymous file descriptor containing bytecode,
// rewound to offset 0 and ready to be handed to bubblewrap via --add-seccomp-fd.
func CreateMemfd(name string, bytecode []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		// Fallback for kernels or container environments where memfd_create is restricted
		tmp, tmpErr := os.CreateTemp("", name+"-*")
		if tmpErr != nil {
			return nil, fmt.Errorf("seccomp memfd fallback: %w (memfd_create failed: %s)", tmpErr, err.Error())
		}
		_ = os.Remove(tmp.Name()) // unlinked immediately
		if _, writeErr := tmp.Write(bytecode); writeErr != nil {
			_ = tmp.Close()
			return nil, fmt.Errorf("write seccomp filter: %w", writeErr)
		}
		if _, seekErr := tmp.Seek(0, io.SeekStart); seekErr != nil {
			_ = tmp.Close()
			return nil, fmt.Errorf("seek seccomp filter: %w", seekErr)
		}
		return tmp, nil
	}

	file := os.NewFile(uintptr(fd), name)
	if _, err := file.Write(bytecode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write seccomp memfd: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("seek seccomp memfd: %w", err)
	}
	return file, nil
}
