package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseJustfileImports(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "single and double quoted imports",
			content: `
import 'sandbox.just'
import "ci/build.just"
import unquoted.just
`,
			expected: []string{"sandbox.just", "ci/build.just", "unquoted.just"},
		},
		{
			name: "optional imports and legacy includes",
			content: `
import? 'opt1.just'
import? "opt2.just"
import? opt3.just
!include 'legacy1.just'
!include "legacy2.just"
!include legacy3.just
`,
			expected: []string{"opt1.just", "opt2.just", "opt3.just", "legacy1.just", "legacy2.just", "legacy3.just"},
		},
		{
			name: "comments and inline comments",
			content: `
# import 'commented_out.just'
// import 'double_slash.just'
import 'active.just' # this is an active import
import "active2.just"   # another active one
  # indented comment
  import 'indented.just'
`,
			expected: []string{"active.just", "active2.just", "indented.just"},
		},
		{
			name: "empty and non-import lines",
			content: `
set positional-arguments := true

build:
	echo building

test target:
	just test-internal
`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseJustfileImports(tt.content)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseJustfileImports() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEffectiveTrustAnchors_ImportsAndSandboxJust(t *testing.T) {
	tempDir := t.TempDir()

	// Create directory structure:
	// justfile -> imports 'sandbox.just' and 'ci/docker.just'
	// sandbox.just
	// ci/docker.just -> imports 'common.just'
	// ci/common.just
	// extra/circular1.just -> imports 'circular2.just'
	// extra/circular2.just -> imports 'circular1.just'

	if err := os.MkdirAll(filepath.Join(tempDir, "ci"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "extra"), 0o750); err != nil {
		t.Fatal(err)
	}

	justfileContent := `
import 'sandbox.just'
import 'ci/docker.just'

build:
	echo building
`
	if err := os.WriteFile(filepath.Join(tempDir, "justfile"), []byte(justfileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	sandboxJustContent := `
[private]
delegate *args:
	keg delegate "$@"
`
	if err := os.WriteFile(filepath.Join(tempDir, "sandbox.just"), []byte(sandboxJustContent), 0o600); err != nil {
		t.Fatal(err)
	}

	dockerJustContent := `
import 'common.just'
import? 'missing_optional.just'
import '../outside.just'

docker-build:
	podman build .
`
	if err := os.WriteFile(filepath.Join(tempDir, "ci", "docker.just"), []byte(dockerJustContent), 0o600); err != nil {
		t.Fatal(err)
	}

	commonJustContent := `
TAG := "v1"
`
	if err := os.WriteFile(filepath.Join(tempDir, "ci", "common.just"), []byte(commonJustContent), 0o600); err != nil {
		t.Fatal(err)
	}

	circ1Content := `import 'circular2.just'`
	circ2Content := `import 'circular1.just'`
	if err := os.WriteFile(filepath.Join(tempDir, "extra", "circular1.just"), []byte(circ1Content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "extra", "circular2.just"), []byte(circ2Content), 0o600); err != nil {
		t.Fatal(err)
	}

	unimportedContent := `unimported_task:\n\techo no`
	if err := os.WriteFile(filepath.Join(tempDir, "unimported.just"), []byte(unimportedContent), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		repo     *Repo
		wantList []string
	}{
		{
			name: "auto justfile discovers sandbox.just and recursive imports via import statement",
			repo: &Repo{
				Version: "1",
				DelegatedTasks: DelegatedTasks{
					Exact: []string{"build"},
				},
			},
			wantList: []string{
				"ci/common.just",
				"ci/docker.just",
				"justfile",
				"sandbox.just",
			},
		},
		{
			name: "explicit trust anchor with circular imports",
			repo: &Repo{
				Version: "1",
				TrustAnchors: []string{
					"extra/circular1.just",
				},
			},
			wantList: []string{
				"extra/circular1.just",
				"extra/circular2.just",
			},
		},
		{
			name: "unimported justfiles in repo root are not included",
			repo: func() *Repo {
				return &Repo{
					Version: "1",
					DelegatedTasks: DelegatedTasks{
						Prefixes: []string{"build"},
					},
				}
			}(),
			wantList: []string{
				"ci/common.just",
				"ci/docker.just",
				"justfile",
				"sandbox.just",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EffectiveTrustAnchors(tt.repo, tempDir)
			if err != nil {
				t.Fatalf("EffectiveTrustAnchors error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.wantList) {
				t.Errorf("got %v, want %v", got, tt.wantList)
			}
		})
	}
}
