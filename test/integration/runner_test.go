//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/runner"
)

// TestSandboxDelegation is the WP-M5 §7.2 DoD test (the `just delegate
// container-build` replacement): whitelisted tasks run on the HOST, live
// output streams back, exit codes and hook suppression carry over.
func TestSandboxDelegation(t *testing.T) {
	repo := t.TempDir()
	hooksDir := t.TempDir() // keg-owned, must stay EMPTY

	engine, err := runner.NewEngine(
		config.DelegatedTasks{
			Exact: []string{"write-marker"},
			Raw: []config.RawRule{
				{Cmd: "git", Subcommands: []string{"commit"}},
			},
		},
		config.RunnerCfg{},
	)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	out := &capture{}
	workload := delegationWorkload()
	plan, planErr := planFor(repo, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", workload})
	if planErr != nil {
		t.Fatalf("plan: %v", planErr)
	}
	plan.Stdout = out
	plan.Stderr = out
	plan.EnableRunner = true
	plan.EnvSet[orchestrator.EnvDelegation] = "1"
	plan.HooksDir = hooksDir

	sb, launchErr := orchestrator.Launch(t.Context(), plan)
	if launchErr != nil {
		t.Fatalf("launch: %v", launchErr)
	}
	defer sb.Close()
	if serr := sb.StartRunner(runner.ServerConfig{
		Engine:   engine,
		JustBin:  "/bin/true",
		RepoRoot: repo,
		HooksDir: hooksDir,
	}); serr != nil {
		t.Fatalf("start runner: %v", serr)
	}

	code, waitErr := sb.Wait()
	if waitErr != nil {
		t.Fatalf("wait: %v\noutput:\n%s", waitErr, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}
	assertDelegationOutcome(t, repo, hooksDir, out.String(), engine)
}

type capture struct{ data []byte }

func (c *capture) Write(p []byte) (int, error) {
	c.data = append(c.data, p...)
	return len(p), nil
}

func (c *capture) String() string { return string(c.data) }

func delegationWorkload() string {
	return `
i=0
while [ ! -S /run/keg/runner.sock ] && [ $i -lt 150 ]; do i=$((i+1)); sleep 0.1; done
[ -S /run/keg/runner.sock ] || { echo NO_SOCKET; exit 9; }
keg delegate write-marker
echo RC_EXACT:$?
keg delegate git commit -m "$(printf 'line-one\nline-two')"
echo RC_GIT:$?
keg delegate git push origin main
echo RC_PUSH:$?
`
}

func assertDelegationOutcome(t *testing.T, _, hooksDir, out string, _ *runner.Engine) {
	t.Helper()
	for _, want := range []string{"RC_EXACT:", "RC_GIT:", "RC_PUSH:126"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	entries, derr := os.ReadDir(hooksDir)
	if derr != nil || len(entries) != 0 {
		t.Errorf("hooks dir polluted by delegated jobs: err=%v", derr)
	}
}
