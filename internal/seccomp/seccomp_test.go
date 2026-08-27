package seccomp

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// bpfEmulator executes classic BPF instructions against simulated seccomp_data.
type bpfEmulator struct {
	arch uint32
	nr   int32
}

func (emu *bpfEmulator) run(bytecode []byte) (uint32, error) {
	if len(bytecode)%8 != 0 {
		return 0, unix.EINVAL
	}
	numInst := len(bytecode) / 8
	var a uint32 // accumulator
	pc := 0

	for pc < numInst {
		offset := pc * 8
		code := binary.LittleEndian.Uint16(bytecode[offset : offset+2])
		jt := bytecode[offset+2]
		jf := bytecode[offset+3]
		k := binary.LittleEndian.Uint32(bytecode[offset+4 : offset+8])

		switch code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch k {
			case 0: // offsetof(struct seccomp_data, nr)
				a = uint32(emu.nr)
			case 4: // offsetof(struct seccomp_data, arch)
				a = emu.arch
			default:
				a = 0
			}
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == k {
				pc = pc + 1 + int(jt)
			} else {
				pc = pc + 1 + int(jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return k, nil
		default:
			return 0, unix.EINVAL
		}
	}
	return 0, unix.EINVAL
}

func TestCompile_DefaultActionIsAllow(t *testing.T) {
	t.Parallel()
	p := Profile{
		DefaultAction: unix.SECCOMP_RET_ALLOW,
	}
	bytecode, err := Compile(p, unix.AUDIT_ARCH_X86_64)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	emu := bpfEmulator{
		arch: unix.AUDIT_ARCH_X86_64,
		nr:   0, // read
	}
	res, err := emu.run(bytecode)
	if err != nil {
		t.Fatalf("emulator run failed: %v", err)
	}
	if res != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("expected SECCOMP_RET_ALLOW (0x%x), got 0x%x", unix.SECCOMP_RET_ALLOW, res)
	}
}

func TestCompile_BlockedSyscallMapsToEperm(t *testing.T) {
	t.Parallel()
	p := DefaultProfile()
	bytecode, err := Compile(p, unix.AUDIT_ARCH_X86_64)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	wantBlocked := []int32{
		321, // bpf on amd64
		425, // io_uring_setup on amd64
		426, // io_uring_enter on amd64
		427, // io_uring_register on amd64
		298, // perf_event_open on amd64
		250, // keyctl on amd64
		323, // userfaultfd on amd64
		165, // mount on amd64
		169, // reboot on amd64
	}

	wantEperm := unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA)

	for _, nr := range wantBlocked {
		emu := bpfEmulator{
			arch: unix.AUDIT_ARCH_X86_64,
			nr:   nr,
		}
		res, err := emu.run(bytecode)
		if err != nil {
			t.Fatalf("emulator error on syscall %d: %v", nr, err)
		}
		if res != wantEperm {
			t.Errorf("syscall %d: expected EPERM (0x%x), got 0x%x", nr, wantEperm, res)
		}
	}

	wantAllowed := []int32{
		0,   // read
		1,   // write
		2,   // open
		3,   // close
		39,  // getpid
		59,  // execve
		101, // ptrace (allowed for delve/gdb/strace)
		257, // openat
		291, // epoll_create1
		310, // process_vm_readv (allowed for delve/gdb)
		311, // process_vm_writev (allowed for delve/gdb)
	}

	for _, nr := range wantAllowed {
		emu := bpfEmulator{
			arch: unix.AUDIT_ARCH_X86_64,
			nr:   nr,
		}
		res, err := emu.run(bytecode)
		if err != nil {
			t.Fatalf("emulator error on syscall %d: %v", nr, err)
		}
		if res != unix.SECCOMP_RET_ALLOW {
			t.Errorf("allowed syscall %d: expected ALLOW (0x%x), got 0x%x", nr, unix.SECCOMP_RET_ALLOW, res)
		}
	}
}

func TestCompile_RejectsUnknownSyscallName(t *testing.T) {
	t.Parallel()
	p := Profile{
		DefaultAction: unix.SECCOMP_RET_ALLOW,
		BlockedSyscalls: []SyscallRule{
			{Name: "definitely_not_a_linux_syscall_xyz123"},
		},
	}
	_, err := Compile(p, unix.AUDIT_ARCH_X86_64)
	if err == nil {
		t.Fatal("expected error for unknown syscall name, got nil")
	}
	if !strings.Contains(err.Error(), "unknown syscall") {
		t.Fatalf("expected error containing 'unknown syscall', got %v", err)
	}
}

func TestDefaultProfile_ContainsThreatCriticalSet(t *testing.T) {
	t.Parallel()
	p := DefaultProfile()
	names := make([]string, len(p.BlockedSyscalls))
	for i, r := range p.BlockedSyscalls {
		names[i] = r.Name
	}

	criticalSet := []string{
		"bpf",
		"perf_event_open",
		"io_uring_setup",
		"io_uring_enter",
		"io_uring_register",
		"keyctl",
		"add_key",
		"request_key",
		"userfaultfd",
		"kexec_load",
		"kexec_file_load",
		"init_module",
		"finit_module",
		"delete_module",
		"mount",
		"pivot_root",
		"swapon",
		"swapoff",
		"reboot",
		"lookup_dcookie",
	}

	for _, name := range criticalSet {
		if !slices.Contains(names, name) {
			t.Errorf("DefaultProfile() missing critical syscall %q", name)
		}
	}
}

func TestDefaultProfile_AllowsDeveloperDebugging(t *testing.T) {
	t.Parallel()
	p := DefaultProfile()
	for _, r := range p.BlockedSyscalls {
		if r.Name == "ptrace" || r.Name == "process_vm_readv" || r.Name == "process_vm_writev" {
			t.Errorf("DefaultProfile() must not block %q (needed for dlv, gdb, strace)", r.Name)
		}
	}
}

func TestCompile_ArchitectureMismatch(t *testing.T) {
	t.Parallel()
	p := DefaultProfile()
	bytecode, err := Compile(p, unix.AUDIT_ARCH_X86_64)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Run with i386 arch against x86_64 compiled filter
	emu := bpfEmulator{
		arch: unix.AUDIT_ARCH_I386,
		nr:   0, // read on i386
	}
	res, err := emu.run(bytecode)
	if err != nil {
		t.Fatalf("emulator error: %v", err)
	}
	wantEperm := unix.SECCOMP_RET_ERRNO | (uint32(unix.EPERM) & unix.SECCOMP_RET_DATA)
	if res != wantEperm {
		t.Fatalf("arch mismatch: expected EPERM (0x%x), got 0x%x", wantEperm, res)
	}
}

func TestCompile_UnsupportedNativeArch(t *testing.T) {
	t.Parallel()
	p := DefaultProfile()
	_, err := Compile(p, 0x12345678)
	if err == nil {
		t.Fatal("expected error for unsupported native arch, got nil")
	}
}

func TestCreateMemfd(t *testing.T) {
	t.Parallel()
	data := []byte("hello-seccomp-filter-data")
	f, err := CreateMemfd("test-seccomp", data)
	if err != nil {
		t.Fatalf("CreateMemfd failed: %v", err)
	}
	defer f.Close()

	readBack, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(readBack, data) {
		t.Fatalf("content mismatch: got %q, want %q", readBack, data)
	}
}
