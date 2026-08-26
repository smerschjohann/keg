package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSha256(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "known string",
			data:    []byte("version: \"1\"\n"),
			want:    "23d3858d3d7bd5a76678fc9496bf2c2f756a1676e44f7532ea47476983eaf944",
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sha256(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Sha256(%q) expected error, got nil", tt.data)
				}
				return
			}
			if err != nil {
				t.Fatalf("Sha256(%q) unexpected error: %v", tt.data, err)
			}
			if got != tt.want {
				t.Errorf("Sha256(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestSha256File(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sample.yaml")
	if err := os.WriteFile(filePath, []byte("version: \"1\"\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := Sha256File(filePath)
	if err != nil {
		t.Fatalf("Sha256File: %v", err)
	}
	if got != "23d3858d3d7bd5a76678fc9496bf2c2f756a1676e44f7532ea47476983eaf944" {
		t.Errorf("Sha256File = %q", got)
	}

	// Non-existing file
	_, err = Sha256File(filepath.Join(tempDir, "missing.yaml"))
	if err == nil {
		t.Errorf("expected error on missing file, got nil")
	}
}

func TestTrustPaths(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/config")
	if p := DefaultTrustPath(); p != "/custom/config/keg/trust.yaml" {
		t.Errorf("DefaultTrustPath with XDG = %q", p)
	}
	if p := Path("/override/trust.yaml"); p != "/override/trust.yaml" {
		t.Errorf("Path override = %q", p)
	}
	if p := Path(""); p != "/custom/config/keg/trust.yaml" {
		t.Errorf("Path empty = %q", p)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	home, _ := os.UserHomeDir()
	if p := DefaultTrustPath(); p != filepath.Join(home, ".config", "keg", "trust.yaml") {
		t.Errorf("DefaultTrustPath without XDG = %q", p)
	}
}

func TestCleanRepoKey(t *testing.T) {
	tempDir := t.TempDir()
	realDir := filepath.Join(tempDir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	symlinkDir := filepath.Join(tempDir, "symlink")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cleaned := CleanRepoKey(symlinkDir)
	if cleaned != realDir {
		t.Errorf("CleanRepoKey(%q) = %q, want %q", symlinkDir, cleaned, realDir)
	}
}

func TestTrustLoadSave(t *testing.T) {
	tempDir := t.TempDir()
	trustFile := filepath.Join(tempDir, "trust.yaml")

	// 1. Missing file -> empty store
	store, err := LoadFile(trustFile)
	if err != nil {
		t.Fatalf("LoadFile non-existing: unexpected error: %v", err)
	}
	if len(store.Repos) != 0 {
		t.Errorf("expected 0 repos in empty store, got %d", len(store.Repos))
	}

	// 2. Roundtrip save & load
	now := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	store.Repos["/repo/b"] = Entry{
		CurrentSHA:      "sha-b",
		ApprovedSHA:     "sha-b",
		ApprovedContent: "version: \"1\"\n",
		Updated:         now,
	}
	store.Repos["/repo/a"] = Entry{
		CurrentSHA:      "sha-a",
		ApprovedSHA:     "",
		ApprovedContent: "",
		Updated:         now,
	}

	if err := SaveFile(trustFile, store); err != nil {
		t.Fatalf("SaveFile failed: %v", err)
	}

	loaded, err := LoadFile(trustFile)
	if err != nil {
		t.Fatalf("LoadFile after save failed: %v", err)
	}
	if len(loaded.Repos) != 2 {
		t.Fatalf("loaded.Repos length = %d, want 2", len(loaded.Repos))
	}
	if loaded.Repos["/repo/b"].ApprovedSHA != "sha-b" {
		t.Errorf("repo b ApprovedSHA = %q, want sha-b", loaded.Repos["/repo/b"].ApprovedSHA)
	}

	// Verify deterministic sorting in raw file
	savedBytes, err := os.ReadFile(trustFile)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	posA := strings.Index(string(savedBytes), "/repo/a")
	posB := strings.Index(string(savedBytes), "/repo/b")
	if posA == -1 || posB == -1 || posA > posB {
		t.Errorf("expected /repo/a to appear before /repo/b in YAML, content:\n%s", string(savedBytes))
	}

	// 3. Unknown field in YAML -> strict parsing error
	invalidYAML := []byte(`
repos:
  /repo/a:
    current_sha: "abc"
    unknown_field: 123
`)
	_, err = Load(invalidYAML)
	if err == nil {
		t.Fatalf("Load with unknown field expected error, got nil")
	}
}

func TestTrustIsTrusted(t *testing.T) {
	tests := []struct {
		name       string
		entry      Entry
		currentSHA string
		want       bool
	}{
		{
			name:       "empty approved SHA",
			entry:      Entry{ApprovedSHA: "", CurrentSHA: "abc"},
			currentSHA: "abc",
			want:       false,
		},
		{
			name:       "mismatched SHA",
			entry:      Entry{ApprovedSHA: "abc", CurrentSHA: "def"},
			currentSHA: "def",
			want:       false,
		},
		{
			name:       "matching approved SHA",
			entry:      Entry{ApprovedSHA: "abc", CurrentSHA: "abc"},
			currentSHA: "abc",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTrusted(tt.entry, tt.currentSHA)
			if got != tt.want {
				t.Errorf("IsTrusted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustNoteCurrent(t *testing.T) {
	store := &Store{Repos: make(map[string]Entry)}
	repoPath := "/path/to/repo"
	content1 := []byte("version: \"1\"\n")
	sha1, _ := Sha256(content1)

	changed, err := NoteCurrent(store, repoPath, content1)
	if err != nil {
		t.Fatalf("NoteCurrent failed: %v", err)
	}
	if !changed {
		t.Errorf("NoteCurrent on new repo should report changed=true")
	}

	entry := store.Repos[repoPath]
	if entry.CurrentSHA != sha1 {
		t.Errorf("entry.CurrentSHA = %q, want %q", entry.CurrentSHA, sha1)
	}
	if entry.ApprovedSHA != "" {
		t.Errorf("entry.ApprovedSHA = %q, want empty", entry.ApprovedSHA)
	}
	if entry.Updated.IsZero() {
		t.Errorf("entry.Updated should not be zero")
	}

	// Calling again with same content -> changed=false
	changed2, err := NoteCurrent(store, repoPath, content1)
	if err != nil {
		t.Fatalf("NoteCurrent second time failed: %v", err)
	}
	if changed2 {
		t.Errorf("NoteCurrent with identical content should report changed=false")
	}

	// Calling with modified content -> changed=true
	content2 := []byte("version: \"1\"\nenv:\n  inherit: [FOO]\n")
	sha2, _ := Sha256(content2)
	changed3, err := NoteCurrent(store, repoPath, content2)
	if err != nil {
		t.Fatalf("NoteCurrent with new content failed: %v", err)
	}
	if !changed3 {
		t.Errorf("NoteCurrent with new content should report changed=true")
	}
	if store.Repos[repoPath].CurrentSHA != sha2 {
		t.Errorf("entry.CurrentSHA = %q, want %q", store.Repos[repoPath].CurrentSHA, sha2)
	}
}

func TestTrustApprove(t *testing.T) {
	store := &Store{Repos: make(map[string]Entry)}
	repoPath := "/path/to/repo"
	content := []byte("version: \"1\"\n")
	sha, _ := Sha256(content)

	approvedSHA, err := Approve(store, repoPath, content)
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if approvedSHA != sha {
		t.Errorf("approvedSHA = %q, want %q", approvedSHA, sha)
	}

	entry := store.Repos[repoPath]
	if entry.ApprovedSHA != sha || entry.CurrentSHA != sha {
		t.Errorf("entry = %+v, expected approved and current to be %s", entry, sha)
	}
	if entry.ApprovedContent != string(content) {
		t.Errorf("entry.ApprovedContent = %q, want %q", entry.ApprovedContent, string(content))
	}
	if !IsTrusted(entry, sha) {
		t.Errorf("entry should be trusted")
	}
}

func TestTrustRevoke(t *testing.T) {
	store := &Store{Repos: make(map[string]Entry)}
	repoPath := "/path/to/repo"
	content := []byte("version: \"1\"\n")
	_, _ = Approve(store, repoPath, content)

	Revoke(store, repoPath)
	entry := store.Repos[repoPath]
	if entry.ApprovedSHA != "" || entry.ApprovedContent != "" {
		t.Errorf("after revoke: entry = %+v, want empty approved fields", entry)
	}
}

func TestApproveThenNoteChange(t *testing.T) {
	store := &Store{Repos: make(map[string]Entry)}
	repoPath := "/path/to/repo"
	content1 := []byte("version: \"1\"\n")
	_, err := Approve(store, repoPath, content1)
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	entry := store.Repos[repoPath]
	if !IsTrusted(entry, entry.CurrentSHA) {
		t.Fatalf("expected entry to be trusted right after approve")
	}

	// Now modify repo content and NoteCurrent
	content2 := []byte("version: \"1\"\nenv:\n  inherit: [BAR]\n")
	_, err = NoteCurrent(store, repoPath, content2)
	if err != nil {
		t.Fatalf("NoteCurrent failed: %v", err)
	}

	entryAfter := store.Repos[repoPath]
	if IsTrusted(entryAfter, entryAfter.CurrentSHA) {
		t.Errorf("entry should NOT be trusted after content change, but IsTrusted was true")
	}
}
