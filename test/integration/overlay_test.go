//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/storage"
)

// TestSandboxIsolateCaches proves `--isolate-caches` keeps host-side caches
// unmodified while allowing full read-write operations in the sandbox tmp-overlay.
func TestSandboxIsolateCaches(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".keg.yaml"), `
version: "1"
templates:
  - go
`)
	writeFile(t, filepath.Join(dir, "go.mod"), "module hello\n\ngo 1.24\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() { println(\"hello-isolated-caches\") }\n")

	hostModCache := t.TempDir()
	hostBuildCache := t.TempDir()

	// Initial warm build on host
	warm := exec.Command("go", "build", "-o", "/dev/null", ".")
	warm.Dir = dir
	warm.Env = append(os.Environ(),
		"GOMODCACHE="+hostModCache,
		"GOCACHE="+hostBuildCache,
		"GOFLAGS=-mod=mod",
	)
	if out, err := warm.CombinedOutput(); err != nil {
		t.Fatalf("host warm build failed: %v\n%s", err, out)
	}

	// Count files in hostBuildCache before sandbox run
	var hostFilesBefore int
	_ = filepath.WalkDir(hostBuildCache, func(_ string, d os.DirEntry, _ error) error {
		if !d.IsDir() {
			hostFilesBefore++
		}
		return nil
	})

	script := `cd /repo 2>/dev/null; go version && go build -o hello . && ./hello`
	var out strings.Builder
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.Stdout = &out
	plan.Stderr = &out

	plan.EnvSet["GOTOOLCHAIN"] = "local"
	plan.EnvSet["GOMODCACHE"] = "/home/sandbox/.cache/go/mod"
	plan.EnvSet["GOCACHE"] = "/home/sandbox/.cache/go/build"
	plan.EnvSet["GOFLAGS"] = "-mod=mod"
	// Isolated caches: mounts use MountEphemeral
	plan.Mounts = append(plan.Mounts,
		config.Mount{Src: hostModCache, Dest: plan.EnvSet["GOMODCACHE"], Mode: config.MountEphemeral},
		config.Mount{Src: hostBuildCache, Dest: plan.EnvSet["GOCACHE"], Mode: config.MountEphemeral},
	)
	tc := config.DetectToolchainPaths(exec.LookPath, config.HostGoEnv)
	if tc.GoRoot != "" && tc.GoRootNeedsBind() {
		plan.Mounts = append(plan.Mounts,
			config.Mount{Src: tc.GoRoot, Dest: tc.GoRoot, Mode: config.MountRO})
		plan.ExtraPathDirs = []string{tc.GoRoot + "/bin"}
	}

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "hello-isolated-caches") {
		t.Errorf("offline build/run failed:\n%s", out.String())
	}

	// Count files in hostBuildCache after sandbox run: must NOT increase
	var hostFilesAfter int
	_ = filepath.WalkDir(hostBuildCache, func(_ string, d os.DirEntry, _ error) error {
		if !d.IsDir() {
			hostFilesAfter++
		}
		return nil
	})
	if hostFilesAfter != hostFilesBefore {
		t.Errorf("host build cache modified: files before=%d, after=%d", hostFilesBefore, hostFilesAfter)
	}
}

// TestSandboxIsolatedCacheName proves `--isolated-cache-name` creates persistent
// cache layers that survive sandbox exits and can be reused across runs.
func TestSandboxIsolatedCacheName(t *testing.T) {
	storageBase := "/var/lib/containers/storage/sandbox"
	if _, err := os.Stat(storageBase); err != nil {
		t.Skipf("no persistent disk storage base at %s: %v", storageBase, err)
	}

	cacheName := fmt.Sprintf("itest-cache-%d", time.Now().UnixNano())
	defer func() {
		_ = storage.CleanCache(storageBase, cacheName)
	}()

	cacheDir := filepath.Join(storageBase, "cache-"+cacheName)
	rwDir := filepath.Join(cacheDir, "mod-rw")
	workDir := filepath.Join(cacheDir, "mod-work")
	for _, d := range []string{rwDir, workDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	hostModCache := t.TempDir()
	dir := t.TempDir()
	findBwrap(t)
	writeFile(t, filepath.Join(dir, ".keg.yaml"), repoConfig)

	runInCacheSandbox := func(script string) (string, int) {
		plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
			[]string{"/bin/sh", "-c", script})
		if err != nil {
			t.Fatal(err)
		}
		plan.Mounts = append(plan.Mounts, config.Mount{
			Src:         hostModCache,
			Dest:        "/home/sandbox/.cache/go/mod",
			Mode:        config.MountDisk,
			OverlayRW:   rwDir,
			OverlayWork: workDir,
		})
		var stdout, stderr bytes.Buffer
		plan.Stdout = &stdout
		plan.Stderr = &stderr
		sb, err := orchestrator.Launch(context.Background(), plan)
		if err != nil {
			t.Fatalf("launch: %v", err)
		}
		code, _ := sb.Wait()
		sb.Close()
		return stdout.String(), code
	}

	// Run 1: write a cached marker inside the sandbox mount
	out1, code1 := runInCacheSandbox("echo cached-data > /home/sandbox/.cache/go/mod/marker.txt")
	if code1 != 0 {
		t.Fatalf("run 1 exited %d:\n%s", code1, out1)
	}

	// Verify hostModCache is NOT touched directly
	if _, err := os.Stat(filepath.Join(hostModCache, "marker.txt")); !os.IsNotExist(err) {
		t.Errorf("host mod cache directly modified: %v", err)
	}

	// Run 2: fresh sandbox reading the marker back from the persistent cache layer
	out2, code2 := runInCacheSandbox("cat /home/sandbox/.cache/go/mod/marker.txt")
	if code2 != 0 {
		t.Fatalf("run 2 exited %d:\n%s", code2, out2)
	}
	if strings.TrimSpace(out2) != "cached-data" {
		t.Errorf("run 2 output = %q, want 'cached-data'", out2)
	}

	// Test storage layer lifecycle
	layers, err := storage.List(storageBase)
	if err != nil {
		t.Fatalf("storage.List: %v", err)
	}
	found := false
	for _, l := range layers {
		if l.Type == storage.LayerCache && l.Name == cacheName {
			found = true
			if l.SizeBytes == 0 {
				t.Errorf("cache layer size is 0, want > 0")
			}
		}
	}
	if !found {
		t.Errorf("cache layer %q not found in storage.List: %+v", cacheName, layers)
	}

	// Clean cache layer
	if err := storage.CleanCache(storageBase, cacheName); err != nil {
		t.Fatalf("storage.CleanCache: %v", err)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Errorf("cache directory %s should be deleted", cacheDir)
	}
}
