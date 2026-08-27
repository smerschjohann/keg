// Package seccomp compiles classic BPF (cBPF) filter bytecode for bubblewrap's
// --add-seccomp-fd interface and provides the default syscall blocklist.
package seccomp

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// SyscallRule defines a single syscall to be filtered.
type SyscallRule struct {
	Name  string
	Errno uint16 // 0 defaults to unix.EPERM
}

// Profile holds the default action and rule list for seccomp filtering.
type Profile struct {
	DefaultAction   uint32
	BlockedSyscalls []SyscallRule
}

// NativeArch returns the Linux audit architecture constant corresponding to the
// current runtime.GOARCH.
func NativeArch() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	case "386":
		return unix.AUDIT_ARCH_I386
	case "arm":
		return unix.AUDIT_ARCH_ARM
	case "riscv64":
		return unix.AUDIT_ARCH_RISCV64
	default:
		return 0
	}
}

// DefaultProfile returns the standard default-allow / blocklist profile
// for keg sandboxes (THREAT_MODEL §5.1 / 2026-08-27.3-seccomp-profile §0.2).
func DefaultProfile() Profile {
	blocked := []string{
		// eBPF & Tracing
		"bpf",
		"perf_event_open",

		// Asynchronous I/O subsystem with extensive parser/LPE attack surface
		"io_uring_setup",
		"io_uring_enter",
		"io_uring_register",

		// Note: ptrace, process_vm_readv, and process_vm_writev are intentionally
		// ALLOWED to support developer tooling (dlv, gdb, strace) within the isolated
		// PID namespace.

		// Kernel keyring (persistent cross-sandbox state)
		"keyctl",
		"add_key",
		"request_key",

		// Userfaultfd (heap spray / race exploit primitive)
		"userfaultfd",

		// Kernel module & image loading
		"kexec_load",
		"kexec_file_load",
		"init_module",
		"finit_module",
		"delete_module",

		// System administration & reboot
		"mount",
		"pivot_root",
		"swapon",
		"swapoff",
		"reboot",

		// Legacy / obsolete syscalls
		"lookup_dcookie",
		"sysfs",
		"_sysctl",
		"uselib",
	}

	rules := make([]SyscallRule, len(blocked))
	for i, name := range blocked {
		rules[i] = SyscallRule{
			Name:  name,
			Errno: uint16(unix.EPERM),
		}
	}

	return Profile{
		DefaultAction:   unix.SECCOMP_RET_ALLOW,
		BlockedSyscalls: rules,
	}
}
