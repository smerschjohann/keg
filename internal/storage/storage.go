// Package storage manages persistent overlay layers on disk (listing,
// size calculations, and tiered deletion / Stufenlöschung).
package storage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// LayerType classifies a persistent on-disk layer.
type LayerType string

// Known layer types.
const (
	LayerRepo  LayerType = "repo"
	LayerCache LayerType = "cache"
)

// Layer describes one persistent on-disk layer found in storage_base.
type Layer struct {
	Name      string    // user-facing name (without cache- prefix for cache layers)
	RawName   string    // directory name on disk (e.g. agent-1 or cache-mycache)
	Type      LayerType // LayerRepo or LayerCache
	Path      string    // absolute host path
	SizeBytes int64     // total size on disk in bytes
	ModTime   time.Time // latest modification time across the layer tree
}

// List scans storageBase and returns all persistent repository and cache layers.
// If storageBase does not exist, List returns (nil, nil) without error.
func List(storageBase string) ([]Layer, error) {
	if _, err := os.Stat(storageBase); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(storageBase)
	if err != nil {
		return nil, fmt.Errorf("read storage base %s: %w", storageBase, err)
	}

	layers := make([]Layer, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rawName := entry.Name()
		if strings.HasPrefix(rawName, ".") {
			continue
		}

		layerPath := filepath.Join(storageBase, rawName)
		lType := LayerRepo
		name := rawName
		if strings.HasPrefix(rawName, "cache-") {
			lType = LayerCache
			name = strings.TrimPrefix(rawName, "cache-")
		}

		size, mtime, err := scanTree(layerPath)
		if err != nil {
			// If a directory cannot be read, still include it with zero size.
			info, statErr := entry.Info()
			if statErr == nil {
				mtime = info.ModTime()
			}
		}

		layers = append(layers, Layer{
			Name:      name,
			RawName:   rawName,
			Type:      lType,
			Path:      layerPath,
			SizeBytes: size,
			ModTime:   mtime,
		})
	}

	// Deterministic sort: repo layers first, then cache layers, sorted by Name.
	slices.SortStableFunc(layers, func(a, b Layer) int {
		if a.Type != b.Type {
			if a.Type == LayerRepo {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})

	return layers, nil
}

// scanTree calculates the total byte size and latest modification time in path.
func scanTree(root string) (int64, time.Time, error) {
	var totalSize int64
	var latestMod time.Time

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() {
			totalSize += info.Size()
		}
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
		}
		return nil
	})

	return totalSize, latestMod, err
}

// Remove deletes a directory tree using the tiered deletion strategy
// (Stufenlöschung: chmod 0700/0600 → unshare -r mount → sudo).
//
// OverlayFS workdirs are created with mode 0000 by bwrap/kernel; standard
// os.RemoveAll fails without prior chmod.
func Remove(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	// Tier 1: chmod recursive to fix mode 0000 on overlay workdirs, then RemoveAll.
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o700) // #nosec G302,G122 -- required for repairing bwrap workdir 0000 mode during deletion
		} else {
			_ = os.Chmod(p, 0o600) // #nosec G122 -- path traversal safe during deletion of user-owned layer
		}
		return nil
	})

	if err := os.RemoveAll(path); err == nil {
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Tier 2: unshare user/mount namespace (fixes unprivileged root-mapped ownership).
	if unshareBin, err := exec.LookPath("unshare"); err == nil && unshareBin != "" {
		cmd := exec.CommandContext(ctx, unshareBin, "-r", "--mount", "rm", "-rf", path) // #nosec G204 -- fixed binary and args
		_ = cmd.Run()
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return nil
		}
	}

	// Tier 3: sudo rm -rf fallback (if non-interactive or interactive sudo is possible).
	if sudoBin, err := exec.LookPath("sudo"); err == nil && sudoBin != "" {
		cmd := exec.CommandContext(ctx, sudoBin, "-n", "rm", "-rf", path) // #nosec G204 -- non-interactive sudo attempt
		_ = cmd.Run()
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return nil
		}
	}

	// If it still exists, return the final error.
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil
	}
	return os.RemoveAll(path)
}

// CleanRepo deletes a persistent repo layer by name.
func CleanRepo(storageBase, name string) error {
	if name == "" {
		return fmt.Errorf("layer name is required")
	}
	target := filepath.Join(storageBase, name)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("layer %q not found in %s", name, storageBase)
	}
	return Remove(target)
}

// CleanCache deletes a specific cache layer (if name != "") or all cache layers (if name == "").
func CleanCache(storageBase, name string) error {
	if name == "" {
		return CleanAllCaches(storageBase)
	}
	target := filepath.Join(storageBase, "cache-"+name)
	if _, err := os.Stat(target); os.IsNotExist(err) {
		return fmt.Errorf("cache layer %q not found in %s", name, storageBase)
	}
	return Remove(target)
}

// CleanAllCaches deletes all cache-* directories under storageBase.
func CleanAllCaches(storageBase string) error {
	if _, err := os.Stat(storageBase); os.IsNotExist(err) {
		return nil
	}
	entries, err := os.ReadDir(storageBase)
	if err != nil {
		return fmt.Errorf("read storage base %s: %w", storageBase, err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "cache-") {
			if err := Remove(filepath.Join(storageBase, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanAllRepos deletes all non-cache directories under storageBase.
func CleanAllRepos(storageBase string) error {
	if _, err := os.Stat(storageBase); os.IsNotExist(err) {
		return nil
	}
	entries, err := os.ReadDir(storageBase)
	if err != nil {
		return fmt.Errorf("read storage base %s: %w", storageBase, err)
	}
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), "cache-") && !strings.HasPrefix(entry.Name(), ".") {
			if err := Remove(filepath.Join(storageBase, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanAll deletes all repo and cache layers under storageBase.
func CleanAll(storageBase string) error {
	if _, err := os.Stat(storageBase); os.IsNotExist(err) {
		return nil
	}
	entries, err := os.ReadDir(storageBase)
	if err != nil {
		return fmt.Errorf("read storage base %s: %w", storageBase, err)
	}
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			if err := Remove(filepath.Join(storageBase, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// FormatSize formats a byte count into a human-readable size string.
func FormatSize(bytes int64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case bytes >= gib:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/float64(gib))
	case bytes >= mib:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/float64(mib))
	case bytes >= kib:
		return fmt.Sprintf("%.1f KiB", float64(bytes)/float64(kib))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
