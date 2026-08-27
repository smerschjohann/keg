package trust

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatDiff(t *testing.T) {
	t.Run("new repo config", func(t *testing.T) {
		newContent := "version: \"1\"\nenv:\n  inherit:\n    - LANG\n"
		diff := FormatDiff("", newContent, true)
		if !strings.Contains(diff, "=== New repository configuration ===") {
			t.Errorf("expected new config header, got:\n%s", diff)
		}
		if !strings.Contains(diff, "version: \"1\"") || !strings.Contains(diff, "LANG") {
			t.Errorf("expected content in diff, got:\n%s", diff)
		}
	})

	t.Run("changed repo config", func(t *testing.T) {
		oldContent := "version: \"1\"\nenv:\n  inherit:\n    - LANG\n"
		newContent := "version: \"1\"\nenv:\n  inherit:\n    - LANG\n    - TERM\n"
		diff := FormatDiff(oldContent, newContent, false)
		if !strings.Contains(diff, "--- approved") || !strings.Contains(diff, "+++ current") {
			t.Errorf("expected diff headers, got:\n%s", diff)
		}
		if !strings.Contains(diff, "+     - TERM") {
			t.Errorf("expected + added line, got:\n%s", diff)
		}
	})
}

func TestEnsureTrust_EmptyOrMissingFile(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}

	// 1. Missing file -> approved without prompt or entry
	approved, err := EnsureTrust(context.Background(), store, tempDir, filepath.Join(tempDir, ".keg.yaml"), nil, nil, nil)
	if err != nil || !approved {
		t.Fatalf("missing file: approved=%v, err=%v", approved, err)
	}
	if len(store.Repos) != 0 {
		t.Errorf("store should not have entries for missing file")
	}

	// 2. Empty file -> approved without prompt or entry
	emptyPath := filepath.Join(tempDir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	approved2, err := EnsureTrust(context.Background(), store, tempDir, emptyPath, nil, nil, nil)
	if err != nil || !approved2 {
		t.Fatalf("empty file: approved=%v, err=%v", approved2, err)
	}
	if len(store.Repos) != 0 {
		t.Errorf("store should not have entries for empty file")
	}
}

func TestEnsureTrust_Trusted(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	content := []byte("version: \"1\"\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Pre-approve
	_, _ = Approve(store, tempDir, content, nil)

	// EnsureTrust with nil stdin/stdout -> must return true immediately
	approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, nil, nil, nil)
	if err != nil || !approved {
		t.Fatalf("pre-approved config: approved=%v, err=%v", approved, err)
	}
}

func TestEnsureTrust_NewNonTTY(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	content := []byte("version: \"1\"\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	sha, _ := Sha256(content)

	stdin := strings.NewReader("yes\n")
	var stdout bytes.Buffer
	isTerm := func(_ any) bool { return false } // non-TTY

	approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, stdin, &stdout, isTerm)
	if approved {
		t.Errorf("expected approved=false for non-TTY untrusted repo")
	}
	if err == nil {
		t.Errorf("expected error for non-TTY untrusted repo, got nil")
	}
	if !strings.Contains(err.Error(), "keg trust") {
		t.Errorf("error %q should mention 'keg trust'", err.Error())
	}

	// CurrentSHA should be written, but ApprovedSHA must be empty
	key := CleanRepoKey(tempDir)
	entry := store.Repos[key]
	if entry.CurrentSHA != sha {
		t.Errorf("entry.CurrentSHA = %q, want %q", entry.CurrentSHA, sha)
	}
	if entry.ApprovedSHA != "" {
		t.Errorf("entry.ApprovedSHA = %q, want empty", entry.ApprovedSHA)
	}
}

func TestEnsureTrust_NewTTY_YesNo(t *testing.T) {
	tests := []struct {
		input        string
		wantApproved bool
		wantErr      bool
	}{
		{input: "yes\n", wantApproved: true, wantErr: false},
		{input: "y\n", wantApproved: true, wantErr: false},
		{input: "ja\n", wantApproved: true, wantErr: false},
		{input: "j\n", wantApproved: true, wantErr: false},
		{input: "YES\n", wantApproved: true, wantErr: false},
		{input: "no\n", wantApproved: false, wantErr: true},
		{input: "nein\n", wantApproved: false, wantErr: true},
		{input: "n\n", wantApproved: false, wantErr: true},
		{input: "\n", wantApproved: false, wantErr: true},
	}

	for _, tt := range tests {
		t.Run("input_"+strings.TrimSpace(tt.input), func(t *testing.T) {
			tempDir := t.TempDir()
			store := &Store{Repos: make(map[string]Entry)}
			cfgPath := filepath.Join(tempDir, ".keg.yaml")
			content := []byte("version: \"1\"\n")
			if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
				t.Fatalf("write file: %v", err)
			}
			sha, _ := Sha256(content)

			stdin := strings.NewReader(tt.input)
			var stdout bytes.Buffer
			isTerm := func(_ any) bool { return true } // TTY

			approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, stdin, &stdout, isTerm)
			if approved != tt.wantApproved {
				t.Errorf("approved = %v, want %v", approved, tt.wantApproved)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(stdout.String(), sha) {
				t.Errorf("prompt stdout should contain checksum %s, got:\n%s", sha, stdout.String())
			}

			key := CleanRepoKey(tempDir)
			entry := store.Repos[key]
			if entry.CurrentSHA != sha {
				t.Errorf("entry.CurrentSHA = %q, want %q", entry.CurrentSHA, sha)
			}
			if tt.wantApproved {
				if entry.ApprovedSHA != sha {
					t.Errorf("entry.ApprovedSHA = %q, want %q", entry.ApprovedSHA, sha)
				}
				if entry.ApprovedContent != string(content) {
					t.Errorf("entry.ApprovedContent = %q, want %q", entry.ApprovedContent, string(content))
				}
			} else {
				if entry.ApprovedSHA != "" {
					t.Errorf("entry.ApprovedSHA = %q, want empty", entry.ApprovedSHA)
				}
			}
		})
	}
}

func TestEnsureTrust_Changed(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	content1 := []byte("version: \"1\"\n")
	if err := os.WriteFile(cfgPath, content1, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// 1. Initial approve
	sha1, _ := Approve(store, tempDir, content1, nil)

	// 2. Change content
	content2 := []byte("version: \"1\"\nenv:\n  inherit: [VAR]\n")
	if err := os.WriteFile(cfgPath, content2, 0o600); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	// User answers "no"
	stdin := strings.NewReader("no\n")
	var stdout bytes.Buffer
	isTerm := func(_ any) bool { return true }

	approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, stdin, &stdout, isTerm)
	if approved || err == nil {
		t.Errorf("expected rejection on 'no', got approved=%v, err=%v", approved, err)
	}

	// Verify ApprovedSHA is still old sha1
	key := CleanRepoKey(tempDir)
	entry := store.Repos[key]
	if entry.ApprovedSHA != sha1 {
		t.Errorf("entry.ApprovedSHA = %q, want %q", entry.ApprovedSHA, sha1)
	}
	sha2, _ := Sha256(content2)
	if entry.CurrentSHA != sha2 {
		t.Errorf("entry.CurrentSHA = %q, want %q", entry.CurrentSHA, sha2)
	}
}

func TestEnsureTrustFile(t *testing.T) {
	tempDir := t.TempDir()
	trustPath := filepath.Join(tempDir, "trust.yaml")
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	content := []byte("version: \"1\"\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// TTY with yes -> approved and trust file created
	stdin := strings.NewReader("yes\n")
	var stdout bytes.Buffer
	isTerm := func(_ any) bool { return true }

	approved, err := EnsureTrustFile(context.Background(), trustPath, tempDir, cfgPath, stdin, &stdout, isTerm)
	if !approved || err != nil {
		t.Fatalf("EnsureTrustFile failed: approved=%v, err=%v", approved, err)
	}

	// Verify trust.yaml was written
	store, err := LoadFile(trustPath)
	if err != nil {
		t.Fatalf("load trust file: %v", err)
	}
	key := CleanRepoKey(tempDir)
	if store.Repos[key].ApprovedSHA == "" {
		t.Errorf("expected approved SHA in store, got empty")
	}
}

func TestIsTerminal(t *testing.T) {
	// A bytes.Buffer or nil is not a terminal
	if IsTerminal(&bytes.Buffer{}) {
		t.Errorf("bytes.Buffer should not be a terminal")
	}
	if IsTerminal(nil) {
		t.Errorf("nil should not be a terminal")
	}
}

func TestFormatAnchorDiff(t *testing.T) {
	t.Run("new anchor file", func(t *testing.T) {
		newContent := "build:\n\techo test\n"
		diff := FormatAnchorDiff("justfile", "", newContent, true)
		if !strings.Contains(diff, "=== New trust anchor: justfile ===") {
			t.Errorf("expected header in diff, got:\n%s", diff)
		}
		if !strings.Contains(diff, "+ build:") {
			t.Errorf("expected + build: in diff, got:\n%s", diff)
		}
	})

	t.Run("changed anchor file", func(t *testing.T) {
		oldContent := "all:\n\techo old\n"
		newContent := "all:\n\techo new\n"
		diff := FormatAnchorDiff("Makefile", oldContent, newContent, false)
		if !strings.Contains(diff, "=== Trust anchor: Makefile ===") {
			t.Errorf("expected header in diff, got:\n%s", diff)
		}
		if !strings.Contains(diff, "- \techo old") || !strings.Contains(diff, "+ \techo new") {
			t.Errorf("expected changes in diff, got:\n%s", diff)
		}
	})
}

func TestEnsureTrust_WithAnchors_TTY_Approve(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	cfgContent := []byte("version: \"1\"\ntrust_anchors:\n  - Makefile\n")
	if err := os.WriteFile(cfgPath, cfgContent, 0o600); err != nil {
		t.Fatal(err)
	}

	makePath := filepath.Join(tempDir, "Makefile")
	makeContent := []byte("all:\n\techo ok\n")
	if err := os.WriteFile(makePath, makeContent, 0o600); err != nil {
		t.Fatal(err)
	}

	stdin := strings.NewReader("yes\n")
	var stdout bytes.Buffer
	isTerm := func(_ any) bool { return true }

	approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, stdin, &stdout, isTerm)
	if !approved || err != nil {
		t.Fatalf("EnsureTrust failed: approved=%v, err=%v", approved, err)
	}

	key := CleanRepoKey(tempDir)
	entry := store.Repos[key]
	makeSHA, _ := Sha256(makeContent)
	if entry.Anchors["Makefile"].ApprovedSHA != makeSHA {
		t.Errorf("Makefile ApprovedSHA = %q, want %q", entry.Anchors["Makefile"].ApprovedSHA, makeSHA)
	}

	// Now modify Makefile
	newMakeContent := []byte("all:\n\techo updated\n")
	if err := os.WriteFile(makePath, newMakeContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Re-run in TTY with yes -> prompts for updated Makefile
	stdin2 := strings.NewReader("yes\n")
	var stdout2 bytes.Buffer
	approved2, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, stdin2, &stdout2, isTerm)
	if !approved2 || err != nil {
		t.Fatalf("EnsureTrust second time failed: approved=%v, err=%v", approved2, err)
	}
	newMakeSHA, _ := Sha256(newMakeContent)
	entry2 := store.Repos[key]
	if entry2.Anchors["Makefile"].ApprovedSHA != newMakeSHA {
		t.Errorf("Makefile ApprovedSHA after re-approval = %q, want %q", entry2.Anchors["Makefile"].ApprovedSHA, newMakeSHA)
	}
}

func TestEnsureTrust_WithAnchors_NonTTY_Rejection(t *testing.T) {
	tempDir := t.TempDir()
	store := &Store{Repos: make(map[string]Entry)}
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	cfgContent := []byte("version: \"1\"\ntrust_anchors:\n  - justfile\n")
	if err := os.WriteFile(cfgPath, cfgContent, 0o600); err != nil {
		t.Fatal(err)
	}

	justPath := filepath.Join(tempDir, "justfile")
	justContent := []byte("build:\n\techo build\n")
	if err := os.WriteFile(justPath, justContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Approve initial state
	anchorContents := map[string][]byte{"justfile": justContent}
	_, err := Approve(store, tempDir, cfgContent, anchorContents)
	if err != nil {
		t.Fatal(err)
	}

	// Modify justfile
	modifiedJustContent := []byte("build:\n\techo malicious\n")
	if err := os.WriteFile(justPath, modifiedJustContent, 0o600); err != nil {
		t.Fatal(err)
	}

	isTerm := func(_ any) bool { return false } // non-TTY
	approved, err := EnsureTrust(context.Background(), store, tempDir, cfgPath, nil, nil, isTerm)
	if approved {
		t.Errorf("expected approved=false for modified anchor in non-TTY")
	}
	if err == nil {
		t.Errorf("expected error for modified anchor in non-TTY, got nil")
	}
}

func TestVerifyApproved(t *testing.T) {
	tempDir := t.TempDir()
	trustPath := filepath.Join(tempDir, "trust.yaml")
	cfgPath := filepath.Join(tempDir, ".keg.yaml")
	cfgContent := []byte("version: \"1\"\ntrust_anchors:\n  - justfile\n")
	if err := os.WriteFile(cfgPath, cfgContent, 0o600); err != nil {
		t.Fatal(err)
	}
	justPath := filepath.Join(tempDir, "justfile")
	justContent := []byte("build:\n\techo build\n")
	if err := os.WriteFile(justPath, justContent, 0o600); err != nil {
		t.Fatal(err)
	}

	store := &Store{Repos: make(map[string]Entry)}
	_, err := Approve(store, tempDir, cfgContent, map[string][]byte{"justfile": justContent})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveFile(trustPath, store); err != nil {
		t.Fatal(err)
	}

	// 1. Valid state
	if err := VerifyApproved(trustPath, tempDir, cfgPath); err != nil {
		t.Fatalf("VerifyApproved failed on valid state: %v", err)
	}

	// 2. Modified justfile -> error
	if err := os.WriteFile(justPath, []byte("build:\n\tmalicious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyApproved(trustPath, tempDir, cfgPath); err == nil {
		t.Errorf("expected VerifyApproved error on modified justfile, got nil")
	}
}
