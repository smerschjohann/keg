package landlock

import (
	"testing"
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
