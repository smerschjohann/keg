package landlock

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLandlock_ModeOff(t *testing.T) {
	err := Restrict(RulesetConfig{
		Mode:         ModeOff,
		ReadOnlyDirs: []string{"/"},
		WritableDirs: []string{"/tmp"},
	})
	if err != nil {
		t.Fatalf("ModeOff should never return error, got: %v", err)
	}
}

func TestLandlock_ModeAuto(t *testing.T) {
	err := Restrict(RulesetConfig{
		Mode:         ModeAuto,
		ReadOnlyDirs: []string{"/"},
		WritableDirs: []string{"/tmp"},
	})
	if err != nil {
		t.Fatalf("ModeAuto should not fail hard on unsupported kernels, got: %v", err)
	}
}

func TestLandlock_Available(t *testing.T) {
	// Must execute without panic
	avail := Available()
	t.Logf("Landlock available on current kernel: %v", avail)
}

func TestLandlock_ModeOn(t *testing.T) {
	avail := Available()
	err := Restrict(RulesetConfig{
		Mode:         ModeOn,
		ReadOnlyDirs: []string{"/"},
		WritableDirs: []string{"/tmp"},
	})
	if avail && err != nil {
		t.Fatalf("ModeOn on supported kernel failed: %v", err)
	}
	if !avail && err == nil {
		t.Fatal("ModeOn on unsupported kernel must return error")
	}
}

func TestLandlockRulesetAttrSize_OnlyHandledAccessFS(t *testing.T) {
	// The kernel rejects a ruleset attribute that is larger than the struct it
	// knows with E2BIG (copy_min_struct_from_user). x/sys grows the struct with
	// every newer kernel ABI, so passing unsafe.Sizeof(attr) would silently
	// disable Landlock on kernels that only know the smaller layout. keg only
	// populates handled_access_fs (ABI 1), so the size must stay at that width.
	want := unsafe.Sizeof(unix.LandlockRulesetAttr{}.Handled_access_fs)
	if landlockRulesetAttrSize != want {
		t.Fatalf("ruleset attr size = %d, want %d (handled_access_fs only)", landlockRulesetAttrSize, want)
	}
}
