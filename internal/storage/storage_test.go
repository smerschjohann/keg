package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestList_NonExistentDir(t *testing.T) {
	layers, err := List("/path/does/not/exist/for/sure")
	if err != nil {
		t.Fatalf("List non-existent dir should not error, got: %v", err)
	}
	if len(layers) != 0 {
		t.Fatalf("List non-existent dir want 0 layers, got %d", len(layers))
	}
}

func TestList_DiscoversRepoAndCacheLayers(t *testing.T) {
	base := t.TempDir()

	// Repo layer "agent-alpha"
	agentDir := filepath.Join(base, "agent-alpha")
	if err := os.MkdirAll(filepath.Join(agentDir, "rw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentDir, "rw", "file.txt"), []byte("hello alpha"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Cache layer "cache-gobuild"
	cacheDir := filepath.Join(base, "cache-gobuild")
	if err := os.MkdirAll(filepath.Join(cacheDir, "mod-rw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "mod-rw", "pkg.mod"), []byte("module data"), 0o644); err != nil {
		t.Fatal(err)
	}

	layers, err := List(base)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(layers) != 2 {
		t.Fatalf("List found %d layers, want 2: %+v", len(layers), layers)
	}

	// Deterministically sorted: repo first, then cache (or alphabetical)
	var repoLayer, cacheLayer *Layer
	for i := range layers {
		if layers[i].Type == LayerRepo {
			repoLayer = &layers[i]
		}
		if layers[i].Type == LayerCache {
			cacheLayer = &layers[i]
		}
	}

	if repoLayer == nil || repoLayer.Name != "agent-alpha" || repoLayer.RawName != "agent-alpha" {
		t.Errorf("repo layer = %+v, want Name=agent-alpha", repoLayer)
	}
	if repoLayer.SizeBytes == 0 {
		t.Errorf("repo layer SizeBytes = 0, want > 0")
	}

	if cacheLayer == nil || cacheLayer.Name != "gobuild" || cacheLayer.RawName != "cache-gobuild" {
		t.Errorf("cache layer = %+v, want Name=gobuild RawName=cache-gobuild", cacheLayer)
	}
	if cacheLayer.SizeBytes == 0 {
		t.Errorf("cache layer SizeBytes = 0, want > 0")
	}
}

func TestRemove_Tier1ChmodWorkdir0000(t *testing.T) {
	base := t.TempDir()
	layerDir := filepath.Join(base, "locked-layer")
	workDir := filepath.Join(layerDir, "work", "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "hidden.bin"), []byte("nested"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate bwrap 0000 permissions on overlay workdir:
	if err := os.Chmod(workDir, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(layerDir, "work"), 0o000); err != nil {
		t.Fatal(err)
	}

	if err := Remove(layerDir); err != nil {
		t.Fatalf("Remove locked layer failed: %v", err)
	}

	if _, err := os.Stat(layerDir); !os.IsNotExist(err) {
		t.Fatalf("layerDir should not exist after Remove, stat err=%v", err)
	}
}

func TestCleanRepo(t *testing.T) {
	base := t.TempDir()
	layerDir := filepath.Join(base, "my-agent")
	if err := os.MkdirAll(filepath.Join(layerDir, "rw"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Missing name
	if err := CleanRepo(base, ""); err == nil {
		t.Error("CleanRepo with empty name should error")
	}

	// Non-existent layer
	if err := CleanRepo(base, "non-existent"); err == nil {
		t.Error("CleanRepo non-existent should error")
	}

	// Success
	if err := CleanRepo(base, "my-agent"); err != nil {
		t.Fatalf("CleanRepo: %v", err)
	}
	if _, err := os.Stat(layerDir); !os.IsNotExist(err) {
		t.Error("my-agent directory should be deleted")
	}
}

func TestCleanCache(t *testing.T) {
	base := t.TempDir()
	c1 := filepath.Join(base, "cache-c1")
	c2 := filepath.Join(base, "cache-c2")
	repo := filepath.Join(base, "repo-layer")
	for _, d := range []string{c1, c2, repo} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Clean single cache
	if err := CleanCache(base, "c1"); err != nil {
		t.Fatalf("CleanCache c1: %v", err)
	}
	if _, err := os.Stat(c1); !os.IsNotExist(err) {
		t.Error("cache-c1 should be deleted")
	}
	if _, err := os.Stat(c2); err != nil {
		t.Error("cache-c2 should still exist")
	}

	// Clean all caches
	if err := CleanAllCaches(base); err != nil {
		t.Fatalf("CleanAllCaches: %v", err)
	}
	if _, err := os.Stat(c2); !os.IsNotExist(err) {
		t.Error("cache-c2 should be deleted")
	}
	if _, err := os.Stat(repo); err != nil {
		t.Error("repo layer should not be deleted by CleanAllCaches")
	}
}

func TestCleanAll(t *testing.T) {
	base := t.TempDir()
	c1 := filepath.Join(base, "cache-c1")
	repo := filepath.Join(base, "repo-1")
	for _, d := range []string{c1, repo} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := CleanAll(base); err != nil {
		t.Fatalf("CleanAll: %v", err)
	}
	layers, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 0 {
		t.Errorf("layers after CleanAll = %d, want 0", len(layers))
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, tt := range tests {
		if got := FormatSize(tt.bytes); got != tt.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}
