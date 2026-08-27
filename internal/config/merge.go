package config

import (
	"maps"
	"os"
	"path"
	"slices"
	"strings"
)

// MergeUsers merges a repo-matched user-config override into the global
// scope: scalars are replaced (only when declared), lists union, maps merge
// keywise. Neither input is modified.
func MergeUsers(global, override *User) *User {
	out := &User{}
	*out = *global

	out.Paths = mergePaths(global.Paths, &override.Paths)
	if override.Runner.JustBin != "" {
		out.Runner.JustBin = override.Runner.JustBin
	}
	out.Runner.ExtraExact = union(global.Runner.ExtraExact, override.Runner.ExtraExact)
	out.Runner.ExtraPrefixes = union(global.Runner.ExtraPrefixes, override.Runner.ExtraPrefixes)
	out.Vars = mergeStringMaps(global.Vars, override.Vars)
	out.InjectNeeds = append(slices.Clone(global.InjectNeeds), override.InjectNeeds...)
	out.Mounts = append(slices.Clone(global.Mounts), override.Mounts...)
	out.Network = mergeNetwork(global.Network, override.Network)
	out.Env = mergeEnv(global.Env, override.Env)
	return out
}

func mergeNetwork(base, over Network) Network {
	out := base
	if over.Mode != "" {
		out.Mode = over.Mode
	}
	if over.DNS.Enabled {
		out.DNS.Enabled = true
	}
	if over.DNS.Upstream != "" {
		out.DNS.Upstream = over.DNS.Upstream
	}
	out.DNS.Hosts = mergeStringMaps(base.DNS.Hosts, over.DNS.Hosts)
	out.SNIDomains = union(base.SNIDomains, over.SNIDomains)
	out.TCPEndpoints = append(slices.Clone(base.TCPEndpoints), over.TCPEndpoints...)
	return out
}

// MergeEnv merges over onto base: Set is keywise merged (over wins), Unset
// and Inherit are unioned, and InheritAll is true if either is true.
func MergeEnv(base, over EnvSpec) EnvSpec {
	out := base
	out.Set = mergeStringMaps(base.Set, over.Set)
	out.Unset = union(base.Unset, over.Unset)
	out.Inherit = union(base.Inherit, over.Inherit)
	out.InheritAll = base.InheritAll || over.InheritAll
	return out
}

// MergeEnvChain merges a chain of EnvSpecs in order from lowest to highest
// precedence: userGlobal → repo → repoOverride → cli.
func MergeEnvChain(specs ...EnvSpec) EnvSpec {
	var out EnvSpec
	for _, s := range specs {
		out = MergeEnv(out, s)
	}
	return out
}

func mergeEnv(base, over EnvSpec) EnvSpec {
	return MergeEnv(base, over)
}

func mergePaths(base Paths, over *Paths) Paths {
	if over == nil {
		return base
	}
	out := base
	if over.StorageBase != "" {
		out.StorageBase = over.StorageBase
	}
	if over.TmpBase != "" {
		out.TmpBase = over.TmpBase
	}
	if over.GoModCache != "" {
		out.GoModCache = over.GoModCache
	}
	if over.GoBuildCache != "" {
		out.GoBuildCache = over.GoBuildCache
	}
	return out
}

// MergeStringMaps merges over into base; keys in over take precedence.
func MergeStringMaps(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	maps.Copy(out, base)
	maps.Copy(out, over)
	return out
}

func mergeStringMaps(base, over map[string]string) map[string]string {
	return MergeStringMaps(base, over)
}

// UnionStrings appends elements of add that are not yet present in base,
// preserving order (Freigaben addieren sich — CONCEPT.md §4.8).
func UnionStrings(base, add []string) []string {
	out := slices.Clone(base)
	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func union(base, add []string) []string {
	return UnionStrings(base, add)
}

// FindRepoOverride returns the matching RepoOverride for repoPath from user.Repos if any.
func FindRepoOverride(user *User, repoPath string) (RepoOverride, bool) {
	repoPath = path.Clean(repoPath)

	type candidate struct {
		key      string
		pattern  string
		specific int
	}

	var exactKey string
	best := candidate{specific: -1}
	for key := range user.Repos {
		pattern, err := ExpandPath(key)
		if err != nil {
			continue
		}
		pattern = path.Clean(pattern)
		if pattern == repoPath {
			exactKey = key // exact realpath always wins
			break
		}
		if strings.ContainsAny(pattern, "*?") && globMatches(pattern, repoPath) {
			if spec := literalPrefixLen(pattern); spec > best.specific {
				best = candidate{key: key, pattern: pattern, specific: spec}
			}
		}
	}

	chosen := exactKey
	if chosen == "" {
		chosen = best.key
	}
	if chosen == "" {
		return RepoOverride{}, false
	}
	return user.Repos[chosen], true
}

// MatchRepo returns the effective user config for repoPath: global scope
// with the matching repos[] override merged in. Exact realpath matches win;
// otherwise the glob with the longest literal prefix applies.
func MatchRepo(user *User, repoPath string) *User {
	out := &User{}
	*out = *user
	override, ok := FindRepoOverride(user, repoPath)
	if !ok {
		return out
	}
	return MergeUsers(out, &User{
		Paths:       derefPaths(override.Paths),
		Runner:      derefRunner(override.Runner),
		Vars:        override.Vars,
		Mounts:      override.Mounts,
		Network:     override.Network,
		Env:         override.Env,
		InjectNeeds: override.Secrets,
	})
}

func derefPaths(p *Paths) Paths {
	if p == nil {
		return Paths{}
	}
	return *p
}

func derefRunner(r *RunnerOverride) RunnerCfg {
	if r == nil {
		return RunnerCfg{}
	}
	return RunnerCfg{JustBin: r.JustBin, ExtraExact: r.ExtraExact, ExtraPrefixes: r.ExtraPrefixes, ExtraRaw: r.ExtraRaw}
}

// globMatches reports whether pattern matches path. Unlike filepath.Match,
// '*' crosses '/' boundaries so "~/work/*" matches every repository below
// ~/work — the intuitive repo-grouping semantic.
func globMatches(pattern, path string) bool {
	// greedy two-pointer glob without regexp (no new deps, stdlib only)
	return matchGlob(pattern, path)
}

// matchGlob implements glob matching with '*' crossing separators.
func matchGlob(pattern, s string) bool {
	var px, sx int
	starP, starS := -1, -1
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			starP = px
			starS = sx
			px++
		case starP >= 0:
			starS++
			sx = starS
			px = starP + 1
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// literalPrefixLen measures specificity: number of leading characters
// before the first wildcard character.
func literalPrefixLen(pattern string) int {
	if i := strings.IndexAny(pattern, "*?["); i >= 0 {
		return i
	}
	return len(pattern)
}

// MergeVars merges vars per CONCEPT.md precedence (later wins):
// repo < user-global < repos[match] < KEG_VAR_* environment < cliVars.
func MergeVars(repoVars, userGlobalVars, repoMatchVars map[string]string, cliVars ...map[string]string) map[string]string {
	out := map[string]string{}
	maps.Copy(out, orEmpty(repoVars))
	maps.Copy(out, orEmpty(userGlobalVars))
	maps.Copy(out, orEmpty(repoMatchVars))
	for _, env := range osEnviron() {
		if name, ok := strings.CutPrefix(env, "KEG_VAR_"); ok && name != "" {
			if k, v, found := strings.Cut(name, "="); found {
				out[k] = v
			}
		}
	}
	for _, cv := range cliVars {
		maps.Copy(out, orEmpty(cv))
	}
	return out
}

func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// osEnviron is a seam for tests; production just returns os.Environ().
var osEnviron = os.Environ
