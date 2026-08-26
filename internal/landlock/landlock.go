// Package landlock provides optional defense-in-depth filesystem restrictions
// via Linux Landlock LSM (Kernel >= 5.13) at syscall level (CONCEPT.md §6.1).
package landlock

import (
	"fmt"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Mode controls Landlock LSM enforcement.
type Mode string

// Known Landlock enforcement modes.
const (
	ModeAuto Mode = "auto"
	ModeOn   Mode = "on"
	ModeOff  Mode = "off"
)

// RulesetConfig defines the path permissions for a sandbox process.
type RulesetConfig struct {
	Mode         Mode
	ReadOnlyDirs []string // Directories with full read/execute permissions
	WritableDirs []string // Directories with read, write, create, truncate permissions
}

func landlockCreateRuleset(attr *unix.LandlockRulesetAttr, size uintptr, flags uint32) (int, error) {
	var attrPtr uintptr
	if attr != nil {
		attrPtr = uintptr(unsafe.Pointer(attr)) // #nosec G103 -- Landlock syscall ABI
	}
	r0, _, e1 := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, attrPtr, size, uintptr(flags))
	if int(r0) < 0 {
		return -1, e1
	}
	return int(r0), nil
}

func landlockAddRule(rulesetFd int, ruleType uint32, ruleAttr unsafe.Pointer, flags uint32) error {
	r0, _, e1 := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFd), uintptr(ruleType), uintptr(ruleAttr), uintptr(flags), 0, 0) // #nosec G103 -- Landlock syscall ABI
	if int(r0) < 0 {
		return e1
	}
	return nil
}

func landlockRestrictSelf(rulesetFd int, flags uint32) error {
	r0, _, e1 := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), uintptr(flags), 0)
	if int(r0) < 0 {
		return e1
	}
	return nil
}

// Available reports whether the running kernel supports Landlock.
func Available() bool {
	// Landlock ABI check: ruleset create with flags = LANDLOCK_CREATE_RULESET_VERSION (1<<0)
	abi, err := landlockCreateRuleset(nil, 0, 1<<0)
	return err == nil && abi > 0
}

// Restrict applies Landlock syscall restrictions to the current process.
//
// In ModeOff: returns nil immediately.
// In ModeAuto: applies if available, logs a debug note and returns nil if unavailable.
// In ModeOn: applies if available, returns error if unavailable or if application fails.
func Restrict(cfg RulesetConfig) error {
	if cfg.Mode == ModeOff {
		return nil
	}

	supported := Available()
	if !supported {
		if cfg.Mode == ModeOn {
			return fmt.Errorf("landlock is required (security.landlock: on) but not supported by kernel")
		}
		slog.Debug("landlock LSM not supported by kernel, proceeding without syscall restrictions")
		return nil
	}

	// 1. Enforce PR_SET_NO_NEW_PRIVS (required before landlock_restrict_self)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		if cfg.Mode == ModeOn {
			return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
		}
		return nil
	}

	// Define full read/execute and write access masks
	const (
		readMask = unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR

		writeMask = readMask |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
			unix.LANDLOCK_ACCESS_FS_REFER |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE
	)

	attr := unix.LandlockRulesetAttr{
		Access_fs: writeMask,
	}

	fd, err := landlockCreateRuleset(&attr, unsafe.Sizeof(attr), 0)
	if err != nil {
		if cfg.Mode == ModeOn {
			return fmt.Errorf("landlock_create_ruleset: %w", err)
		}
		return nil
	}
	defer func() { _ = unix.Close(fd) }()

	// Add read-only directories
	for _, dir := range cfg.ReadOnlyDirs {
		if dir == "" {
			continue
		}
		dfd, openErr := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if openErr != nil {
			continue
		}
		pathAttr := unix.LandlockPathBeneathAttr{
			Parent_fd:      int32(dfd), // #nosec G115 -- fd integer conversion
			Allowed_access: readMask,
		}
		_ = landlockAddRule(fd, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&pathAttr), 0) // #nosec G103 -- Landlock syscall ABI
		_ = unix.Close(dfd)
	}

	// Add writable directories
	for _, dir := range cfg.WritableDirs {
		if dir == "" {
			continue
		}
		dfd, openErr := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if openErr != nil {
			continue
		}
		pathAttr := unix.LandlockPathBeneathAttr{
			Parent_fd:      int32(dfd), // #nosec G115 -- fd integer conversion
			Allowed_access: writeMask,
		}
		_ = landlockAddRule(fd, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&pathAttr), 0) // #nosec G103 -- Landlock syscall ABI
		_ = unix.Close(dfd)
	}

	// Restrict self
	if err := landlockRestrictSelf(fd, 0); err != nil {
		if cfg.Mode == ModeOn {
			return fmt.Errorf("landlock_restrict_self: %w", err)
		}
	}
	return nil
}
