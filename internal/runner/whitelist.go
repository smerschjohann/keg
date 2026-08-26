// Package runner implements delegation channel C: the host-side daemon
// that executes whitelisted tasks on behalf of the sandbox (CONCEPT.md
// §4.5), the argument-pattern whitelist engine, and the wire protocol.
//
// Security model (THREAT_MODEL §5.4): delegated jobs run on the HOST,
// outside the sandbox network policy — the whitelist is therefore
// deny-by-default and every denial is visible with a reason (exit 126).
package runner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/smerschjohann/keg/internal/config"
)

// Kind names how an allowed job must be executed on the host.
type Kind int

const (
	// KindJust runs the task through the configured just binary.
	KindJust Kind = iota
	// KindRaw execs the argv directly on the host (no shell).
	KindRaw
)

// String returns the audit-facing name of the execution kind.
func (k Kind) String() string {
	if k == KindRaw {
		return "raw"
	}
	return "just"
}

// Decision is the outcome of a whitelist check. Denials always carry a
// user-visible reason (it becomes the exit-126 stderr text).
type Decision struct {
	Allow  bool
	Kind   Kind
	Reason string
}

func deny(format string, args ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, args...)}
}

// Engine is the immutable, deny-by-default delegation whitelist. It merges
// the repo's delegated_tasks with the additive extra_* allowlists of the
// user config (CONCEPT.md §5: extras union, nothing is taken away).
type Engine struct {
	exact    map[string]bool
	prefixes map[string]bool
	raw      []config.RawRule // deterministic order preserved for audits
}

// NewEngine validates and combines repo rules with user-config extras.
// Raw rules without a non-empty subcommands set and malformed regex
// patterns are configuration errors (fail-closed before any launch).
func NewEngine(tasks config.DelegatedTasks, extra config.RunnerCfg) (*Engine, error) {
	e := &Engine{
		exact:    map[string]bool{},
		prefixes: map[string]bool{},
		raw:      append(append([]config.RawRule{}, tasks.Raw...), extra.ExtraRaw...),
	}
	for _, name := range append(append([]string{}, tasks.Exact...), extra.ExtraExact...) {
		e.exact[name] = true
	}
	for _, name := range append(append([]string{}, tasks.Prefixes...), extra.ExtraPrefixes...) {
		e.prefixes[name] = true
	}
	for i, rule := range e.raw {
		if len(rule.Subcommands) == 0 {
			return nil, fmt.Errorf("runner whitelist: raw[%d] (%s): subcommands must not be empty", i, rule.Cmd)
		}
		for _, p := range rule.ForbiddenArgsMatching {
			if err := validatePattern(p); err != nil {
				return nil, fmt.Errorf("runner whitelist: raw %q: forbidden_args_matching %q: %w", rule.Cmd, p, err)
			}
		}
	}
	return e, nil
}

// Match decides whether argv may be delegated to the host. The first
// element is the task name; for raw rules it must equal the configured cmd.
func (e *Engine) Match(argv []string) Decision {
	if len(argv) == 0 {
		return deny("empty delegation request")
	}
	task, rest := argv[0], argv[1:]

	switch {
	case e.exact[task] && len(rest) == 0:
		return Decision{Allow: true, Kind: KindJust}
	case e.exact[task]:
		return deny("task %q is exact-only and takes no arguments (%d given)", task, len(rest))
	case e.prefixes[task]:
		return Decision{Allow: true, Kind: KindJust}
	}
	for _, rule := range e.raw {
		if rule.Cmd == task {
			d := MatchRaw(argv, rule)
			if !d.Allow {
				return d
			}
			return Decision{Allow: true, Kind: KindRaw}
		}
	}
	return deny("task %q is not whitelisted for delegation", task)
}

// MatchRaw applies the five-step argument pattern match from CONCEPT.md
// §4.5 to a full argv whose first element should be rule.Cmd:
//
//  1. argv[0] must equal the configured cmd;
//  2. known global options are skipped (opts_with_value consume their
//     following argument; flags stand alone; --opt=value only when
//     allow_opt_value_form);
//  3. the first unknown argument must be in the subcommands set;
//  4. everything after it is checked against forbidden_args_matching
//     (glob or /regex/, per single argument);
//  5. the remainder passes through unchanged.
func MatchRaw(argv []string, rule config.RawRule) Decision {
	if len(argv) == 0 || argv[0] != rule.Cmd {
		return deny("argv[0] %q does not match raw cmd %q", firstOf(argv), rule.Cmd)
	}
	i := 1
scan:
	for i < len(argv) {
		arg := argv[i]
		switch {
		case contains(rule.OptsWithValue, arg):
			if i+1 >= len(argv) {
				return deny("option %q at end of argv is missing its value", arg)
			}
			i += 2 // option consumes its value
		case contains(rule.Flags, arg):
			i++
		case rule.AllowOptValueForm && isOptValueForm(arg, rule.OptsWithValue):
			i++
		default:
			break scan
		}
	}
	if i >= len(argv) {
		return deny("no whitelisted subcommand found in %q invocation", rule.Cmd)
	}
	if !contains(rule.Subcommands, argv[i]) {
		return deny("%q is not a whitelisted %q subcommand", argv[i], rule.Cmd)
	}
	for _, arg := range argv[i+1:] {
		for _, pattern := range rule.ForbiddenArgsMatching {
			if forbiddenMatch(pattern, arg) {
				return deny("argument %q matches forbidden pattern %q", arg, pattern)
			}
		}
	}
	return Decision{Allow: true, Kind: KindRaw}
}

// isOptValueForm reports whether arg has the selfstanding "--opt=value"
// shape with opt among opts (only accepted when allow_opt_value_form).
func isOptValueForm(arg string, opts []string) bool {
	eq := strings.Index(arg, "=")
	if eq <= 2 || !strings.HasPrefix(arg, "--") {
		return false
	}
	return contains(opts, arg[:eq])
}

func firstOf(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return argv[0]
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Pattern forms understood by forbidden_args_matching: "/regex/" or a glob
// where '*' spans any characters INCLUDING '/' and '?' matches exactly one.
var regexForm = regexp.MustCompile(`^/(.*)/$`)

func validatePattern(pattern string) error {
	if m := regexForm.FindStringSubmatch(pattern); m != nil {
		if _, err := regexp.Compile(m[1]); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	}
	return nil // globs are always well-formed
}

// forbiddenMatch reports whether arg hits one forbidden pattern.
func forbiddenMatch(pattern, arg string) bool {
	if m := regexForm.FindStringSubmatch(pattern); m != nil {
		re, err := regexp.Compile(m[1])
		if err != nil {
			return false // unreachable: patterns validated by NewEngine
		}
		return re.MatchString(arg)
	}
	return globMatch(pattern, arg)
}

// globMatch implements the URL-friendly glob: unlike path.Match, '*'
// crosses '/' so "https://evil.example/pwn.git" matches "https://*".
func globMatch(pattern, arg string) bool {
	var sb strings.Builder
	sb.WriteString(`^(?s)`)
	for _, r := range pattern {
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	sb.WriteString("$")
	matched, err := regexp.MatchString(sb.String(), arg)
	return err == nil && matched
}
