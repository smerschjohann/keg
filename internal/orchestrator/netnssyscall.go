package orchestrator

import (
	"errors"
	"os/exec"
)

// Linux capability syscall constants. SYS_CAPSET is 157 on amd64 and arm64
// (the supported targets); stdlib syscall does not export it.
const (
	capVersion1   = 0x19980330 // _LINUX_CAPABILITY_VERSION_1
	sysCallCapset = 157
)

type (
	capHeader struct{ version, pid uint32 }
	capData   struct{ effective, permitted, inheritable uint32 }
)

type ifreqFlags struct {
	name  [16]byte
	flags int16
	pad   [22]byte
}

func exitErrorAs(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}
