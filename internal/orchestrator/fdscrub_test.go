package orchestrator

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// openWithoutCloexec creates a file and opens it with a raw syscall so the
// descriptor has no close-on-exec flag — simulating an inherited foreign fd.
func openWithoutCloexec(t *testing.T, path string) int {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("raw open %s: %v", path, err)
	}
	return fd
}

func hasCloexec(fd int) bool {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		return false
	}
	return flags&syscall.FD_CLOEXEC != 0
}

func TestScrubForeignFDs_MarksStrayDescriptors(t *testing.T) {
	stray := openWithoutCloexec(t, filepath.Join(t.TempDir(), "stray"))
	defer syscall.Close(stray)

	// Scrub everything except stdio; nothing else is kept.
	if err := ScrubForeignFDs(map[int]bool{0: true, 1: true, 2: true}); err != nil {
		t.Fatalf("ScrubForeignFDs: %v", err)
	}

	if !hasCloexec(stray) {
		t.Errorf("stray fd %d did not get FD_CLOEXEC", stray)
	}
	for _, std := range []int{0, 1, 2} {
		if hasCloexec(std) {
			t.Errorf("stdio fd %d must never get FD_CLOEXEC", std)
		}
	}
}

func TestScrubForeignFDs_KeepSetHonored(t *testing.T) {
	a := openWithoutCloexec(t, filepath.Join(t.TempDir(), "a"))
	defer syscall.Close(a)
	b := openWithoutCloexec(t, filepath.Join(t.TempDir(), "b"))
	defer syscall.Close(b)

	if err := ScrubForeignFDs(map[int]bool{a: true}); err != nil {
		t.Fatal(err)
	}
	if hasCloexec(a) {
		t.Errorf("explicitly kept fd %d must stay exec-visible", a)
	}
	if !hasCloexec(b) {
		t.Errorf("non-kept fd %d must be marked cloexec", b)
	}
}

func TestListOpenFDs_ContainsOwnDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fds, err := listOpenFDs()
	if err != nil {
		t.Fatalf("listOpenFDs: %v", err)
	}
	found := false
	for _, fd := range fds {
		if strconv.Itoa(int(f.Fd())) == strconv.Itoa(fd) && fd == int(f.Fd()) {
			found = true
		}
	}
	if !found {
		t.Errorf("own fd %d missing from %v", f.Fd(), fds)
	}
}
