package orchestrator

import (
	"fmt"
	"os"
	"syscall"

	"github.com/moby/sys/reexec"
)

// GuestCommandName is the reexec name under which the sandbox entrypoint
// runs (second invocation of the same binary inside bwrap).
const GuestCommandName = "github.com/smerschjohann/keg/guest"

func init() {
	reexec.Register(GuestCommandName, guestMain)
}

// guestMain is the sandbox-side entrypoint (CODE_KEG=1 invocation).
// It starts the guest bridges in later milestones; for now it enforces env
// hygiene a second time and transparently execs the requested command.
//
// FD contract: fd 3 = proxy channel, fd 4 = DNS, fd 5 = runner
// (see FDProxy/FDDNS/FDRunner).
func guestMain() {
	_ = os.Setenv("CODE_KEG", "1") // best effort; nothing depends on failure modes
	env := StripDeniedEnv(os.Environ(), HostDeniedEnvVars)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "keg guest: no command given")
		os.Exit(127)
	}
	// Replace the process image; environment is the stripped one plus any
	// values set above. No bridges exist yet (WP-M2/M3 wire them up).
	// The command comes from the keg host orchestrator (trusted parent);
	// arbitrary argv is the whole point of this entrypoint.
	err := syscall.Exec(os.Args[1], os.Args[1:], dedupeEnv(env)) // #nosec G702 -- trusted caller (host-side orchestrator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: exec %s: %v\n", os.Args[1], err)
		os.Exit(127)
	}
}

// dedupeEnv keeps the last occurrence of each NAME=value pair.
func dedupeEnv(env []string) []string {
	seen := make(map[string]int) // name -> index in out
	out := make([]string, 0, len(env))
	for _, e := range env {
		name, _ := cutEnvEntry(e)
		if name == "" {
			continue
		}
		if idx, exists := seen[name]; exists {
			out[idx] = e // later value wins
			continue
		}
		seen[name] = len(out)
		out = append(out, e)
	}
	return out
}
