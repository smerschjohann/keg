package orchestrator

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/portsfw"
	"github.com/smerschjohann/keg/internal/runner"
	"github.com/smerschjohann/keg/internal/secrets"
	"github.com/smerschjohann/keg/internal/template"
	"github.com/smerschjohann/keg/internal/trust"
)

var ensureTrustGate = func(repoRoot, cfgPath string) (bool, error) {
	return trust.EnsureTrustFile(context.Background(), trust.DefaultTrustPath(), repoRoot, cfgPath, os.Stdin, os.Stdout, trust.IsTerminal)
}

// IsValidInstanceName validates that an instance name consists only of
// alphanumeric characters, hyphens, and underscores.
func IsValidInstanceName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// BuildPlan parses and validates configuration for a sandbox run and prepares
// the filesystem and orchestrator plan without starting the sandbox.
func BuildPlan(repoDir, repoCfgPath, userCfgPath string, overlay Overlay, diskName string, cacheOverlay Overlay, isolatedCacheName, instanceName string, cliVars ...map[string]string) (Plan, *config.User, error) {
	root := repoDir
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	// Repo config: explicit path or <root>/.keg.yaml (fallback to default).
	cfgPath := repoCfgPath
	if cfgPath == "" {
		cfgPath = filepath.Join(root, ".keg.yaml")
	}

	if _, err := ensureTrustGate(root, cfgPath); err != nil {
		return Plan{}, nil, err
	}

	repo, err := config.LoadRepo(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && repoCfgPath == "" {
			repo = &config.Repo{Version: config.SupportedVersion}
		} else {
			return Plan{}, nil, fmt.Errorf("repo %s: %w (create a .keg.yaml or pass --config)", root, err)
		}
	}

	// User config: optional.
	user := &config.User{}
	userPath := userCfgPath
	if userPath == "" {
		userPath = config.DefaultUserPath()
	}
	if data, err := os.ReadFile(userPath); err == nil { // #nosec G304 -- user config path
		parsed, parseErr := config.ParseUser(data)
		if parseErr != nil {
			return Plan{}, nil, fmt.Errorf("%s: %w", userPath, parseErr)
		}
		user = parsed
	} else if userCfgPath != "" {
		return Plan{}, nil, fmt.Errorf("load user config: %w", err)
	}

	effective := config.MatchRepo(user, root)
	var cliVarsMap map[string]string
	if len(cliVars) > 0 {
		cliVarsMap = cliVars[0]
	}
	vars := config.MergeVars(repo.Vars, effective.Vars, nil, cliVarsMap)

	// Template context: .Vars always, .Env only when user config opts in.
	tctx := template.Context{Vars: vars}
	if effective.TemplateEnv.AllowEnv != nil && *effective.TemplateEnv.AllowEnv {
		tctx.Env = envMap()
	}
	if err := resolveTemplates(repo, tctx); err != nil {
		return Plan{}, nil, err
	}

	allMounts := make([]config.Mount, 0, len(repo.Mounts)+len(effective.Mounts))
	allMounts = append(allMounts, repo.Mounts...)
	allMounts = append(allMounts, effective.Mounts...)

	expandedMounts := make([]config.Mount, 0, len(allMounts))
	for _, m := range allMounts {
		src := m.Src
		if exp, err := config.ExpandPath(src); err == nil && exp != "" {
			src = exp
		}
		m.Src = src
		expandedMounts = append(expandedMounts, m)
	}

	mode := repo.Network.Mode
	if effective.Network.Mode != "" {
		mode = effective.Network.Mode
	}
	sniDomains := config.UnionStrings(repo.Network.SNIDomains, effective.Network.SNIDomains)
	tcpEndpoints := append(slices.Clone(repo.Network.TCPEndpoints), effective.Network.TCPEndpoints...)

	// Env merge chain: User-global -> Repo -> repos[match] override -> CLI
	var overrideEnv config.EnvSpec
	if override, ok := config.FindRepoOverride(user, root); ok {
		overrideEnv = override.Env
	}
	mergedEnv := config.MergeEnvChain(user.Env, repo.Env, overrideEnv)

	// Validate: HostDeniedEnvVars must never be passed through from host env
	for _, name := range mergedEnv.Inherit {
		if slices.Contains(HostDeniedEnvVars, name) {
			return Plan{}, nil, fmt.Errorf("cannot pass through denied host environment variable %q — use explicit setting (-e %s=<value> or env.set) instead", name, name)
		}
	}

	// Conflict resolution: unset beats inherit
	if len(mergedEnv.Unset) > 0 {
		mergedEnv.Inherit = slices.DeleteFunc(mergedEnv.Inherit, func(s string) bool {
			return slices.Contains(mergedEnv.Unset, s)
		})
	}

	plan := Plan{
		RepoRoot:      root,
		RepoCfgPath:   cfgPath,
		SandboxHome:   "/home/sandbox",
		Mounts:        expandedMounts,
		EnvUnset:      mergedEnv.Unset,
		EnvSet:        map[string]string{},
		EnvInherit:    mergedEnv.Inherit,
		EnvInheritAll: mergedEnv.InheritAll,
		BwrapArgs:     repo.BwrapArgs,
		AllowWeakBwrap: effective.Security.AllowWeakBwrap != nil &&
			*effective.Security.AllowWeakBwrap,
		Overlay:      overlay,
		SNIDomains:   sniDomains,
		TCPEndpoints: tcpEndpoints,
		// "both" enables the transparent SNI relay WITHOUT disabling the
		// explicit proxy path — both routes share the host-side policy.
		Transparent: mode == "transparent" || mode == "both",
		Landlock:    effective.Security.Landlock,
		Seccomp:     effective.Security.Seccomp,
	}
	if plan.Landlock == "" {
		plan.Landlock = "auto"
	}
	if plan.Seccomp == "" {
		plan.Seccomp = "auto"
	}
	plan.UpstreamProxy = UpstreamProxyFromEnv(os.Getenv)
	plan.EnvSet[EnvLandlock] = plan.Landlock
	for k, v := range mergedEnv.Set {
		plan.EnvSet[k] = v
	}

	// Host-side temporary instance directory
	tmpBase := effective.Paths.TmpBase
	if expanded, err := config.ExpandPath(tmpBase); err == nil && expanded != "" {
		tmpBase = expanded
	} else {
		tmpBase = os.TempDir()
	}
	if tmpBase != "" {
		_ = os.MkdirAll(tmpBase, 0o750) // #nosec G703 -- trusted user config
	}
	var instanceDir string
	if instanceName != "" {
		if !IsValidInstanceName(instanceName) {
			return Plan{}, nil, fmt.Errorf("invalid instance name %q: must contain only letters, digits, underscores, and hyphens", instanceName)
		}
		instanceDir = filepath.Join(tmpBase, "keg-"+instanceName)
		if err := os.MkdirAll(instanceDir, 0o750); err != nil { // #nosec G703 -- trusted dir
			return Plan{}, nil, fmt.Errorf("create instance dir %s: %w", instanceDir, err)
		}
		plan.InstanceName = instanceName
	} else {
		d, err := os.MkdirTemp(tmpBase, "keg-")
		if err != nil {
			return Plan{}, nil, fmt.Errorf("create instance dir: %w", err)
		}
		instanceDir = d
	}
	plan.TmpDir = instanceDir

	auditPath := effective.Log.AuditFile
	if auditPath == "" {
		auditPath = DefaultAuditPath()
	} else if expanded, err := config.ExpandPath(auditPath); err == nil {
		auditPath = expanded
	}
	plan.AuditFile = auditPath

	// Secrets: resolve every requested name via the user config — either
	// as an existing HOST FILE to bind-mount (secrets map) or as a dynamic
	// secret_sources command fetched before launch and refreshed later.
	// The need list is the union of:
	//   1. the repo's own .keg.yaml `secrets:` declarations,
	//   2. the per-repo `secrets:` need list from the matched repos[]
	//      override (effective.InjectNeeds),
	//   3. every secret_sources entry flagged `always: true` (global
	//      injection into every sandbox, independent of any repo config).
	var secretNeeds []config.SecretRef
	secretNeeds = append(secretNeeds, repo.Secrets...)
	secretNeeds = append(secretNeeds, effective.InjectNeeds...)
	seen := make(map[string]bool, len(secretNeeds))
	for _, n := range secretNeeds {
		seen[n.Name] = true
	}
	for name, src := range effective.SecretSources {
		if src.Always && !seen[name] {
			seen[name] = true
			secretNeeds = append(secretNeeds, config.SecretRef{Name: name})
		}
	}

	if len(secretNeeds) > 0 {
		var fetchRefs []config.SecretRef
		for _, ref := range secretNeeds {
			if rawPath, ok := effective.Secrets[ref.Name]; ok {
				hostPath, err := config.ExpandPath(rawPath)
				if err != nil {
					return Plan{}, nil, fmt.Errorf("secret %q: %w", ref.Name, err)
				}
				if abs, absErr := filepath.Abs(hostPath); absErr == nil {
					hostPath = abs
				}
				info, statErr := os.Stat(hostPath) // #nosec G703 -- path from trusted user config (same trust level as secret_sources cmds); repos supply names only
				if statErr != nil || info.IsDir() {
					return Plan{}, nil, fmt.Errorf("secret %q: host file %q does not exist", ref.Name, rawPath)
				}
				plan.SecretPathBinds = append(plan.SecretPathBinds, SecretBind{
					HostPath:  hostPath,
					GuestPath: "/run/secrets/" + ref.Name,
				})
			} else if _, hasSource := effective.SecretSources[ref.Name]; hasSource {
				fetchRefs = append(fetchRefs, ref)
			} else {
				return Plan{}, nil, fmt.Errorf(
					"secret %q requested by repository is neither defined in secret_sources nor in secrets (both user config)",
					ref.Name)
			}
		}
		if len(fetchRefs) > 0 {
			secretVars := make(map[string]string, len(vars)+2)
			maps.Copy(secretVars, vars)
			instName := plan.InstanceName
			if instName == "" {
				instName = strings.TrimPrefix(filepath.Base(plan.TmpDir), "keg-")
			}
			secretVars["instance"] = instName
			secretVars["repo_dir"] = root
			secretTctx := template.Context{
				Vars: secretVars,
				Env:  tctx.Env,
			}

			secretsDir := filepath.Join(plan.TmpDir, "secrets")
			if err := secrets.FetchInitial(context.Background(), fetchRefs, effective.SecretSources, secretsDir, secretTctx); err != nil {
				return Plan{}, nil, err
			}
			plan.SecretDir = secretsDir
			plan.Secrets = fetchRefs
			plan.SecretSources = effective.SecretSources
			plan.SecretTemplateCtx = secretTctx
		}
		for _, s := range secretNeeds {
			if s.Env != "" {
				plan.EnvSet[s.Env] = "/run/secrets/" + s.Name
			}
		}
	}

	// Language templates
	if len(repo.Templates) > 0 {
		tc := config.DetectToolchainPaths(exec.LookPath, config.HostGoEnv)
		if effective.Paths.GoModCache != "" {
			if exp, expErr := config.ExpandPath(effective.Paths.GoModCache); expErr == nil {
				tc.GoModCache = exp
			}
		}
		if effective.Paths.GoBuildCache != "" {
			if exp, expErr := config.ExpandPath(effective.Paths.GoBuildCache); expErr == nil {
				tc.GoBuildCache = exp
			}
		}
		tplMounts, tplEnv, terr := config.ExpandTemplates(repo.Templates, plan.SandboxHome, tc)
		if terr != nil {
			return Plan{}, nil, fmt.Errorf("templates: %w", terr)
		}
		for _, m := range tplMounts {
			src := m.Src
			if expanded, expErr := config.ExpandPath(src); expErr == nil {
				src = expanded
			}
			mount := config.Mount{Src: src, Dest: m.Dest, Mode: m.Mode}
			if cacheOverlay == OverlayEphemeral {
				mount.Mode = config.MountEphemeral
			} else if cacheOverlay == OverlayDisk && isolatedCacheName != "" {
				mount.Mode = config.MountDisk
				storageBase := effective.Paths.StorageBase
				if storageBase == "" {
					storageBase = "/var/lib/containers/storage/sandbox"
				}
				if expanded, expErr := config.ExpandPath(storageBase); expErr == nil {
					storageBase = expanded
				}
				cacheDir := filepath.Join(storageBase, "cache-"+isolatedCacheName)
				key := filepath.Base(m.Dest)
				if key == "" || key == "." || key == "/" {
					key = "cache"
				}
				rwDir := filepath.Join(cacheDir, key+"-rw")
				workDir := filepath.Join(cacheDir, key+"-work")
				for _, sub := range []string{rwDir, workDir} {
					if mkErr := os.MkdirAll(sub, 0o750); mkErr != nil { // #nosec G703 -- trusted path
						return Plan{}, nil, fmt.Errorf("prepare cache layer %s: %w", cacheDir, mkErr)
					}
				}
				mount.OverlayRW = rwDir
				mount.OverlayWork = workDir
			}
			plan.Mounts = append(plan.Mounts, mount)
		}
		for k, v := range tplEnv {
			if _, exists := plan.EnvSet[k]; !exists {
				plan.EnvSet[k] = v
			}
		}
		if tc.GoRootNeedsBind() {
			plan.Mounts = append(plan.Mounts, config.Mount{Src: tc.GoRoot, Dest: tc.GoRoot, Mode: config.MountRO})
			binDir := tc.GoRoot + "/bin"
			if !slices.Contains(plan.ExtraPathDirs, binDir) {
				plan.ExtraPathDirs = append([]string{binDir}, plan.ExtraPathDirs...)
			}
		}
	}

	// Prepend paths (prepend / extra)
	for _, raw := range append(slices.Clone(repo.Paths.Prepend), repo.Paths.Extra...) {
		if p := resolveExtraPath(raw, root, plan.SandboxHome); p != "" {
			if !slices.Contains(plan.PrependPathDirs, p) {
				plan.PrependPathDirs = append(plan.PrependPathDirs, p)
			}
		}
	}
	for _, raw := range append(slices.Clone(effective.Paths.Prepend), effective.Paths.Extra...) {
		if p := resolveExtraPath(raw, root, plan.SandboxHome); p != "" {
			if !slices.Contains(plan.PrependPathDirs, p) {
				plan.PrependPathDirs = append(plan.PrependPathDirs, p)
			}
		}
	}

	// Append paths
	for _, raw := range repo.Paths.Append {
		if p := resolveExtraPath(raw, root, plan.SandboxHome); p != "" {
			if !slices.Contains(plan.AppendPathDirs, p) {
				plan.AppendPathDirs = append(plan.AppendPathDirs, p)
			}
		}
	}
	for _, raw := range effective.Paths.Append {
		if p := resolveExtraPath(raw, root, plan.SandboxHome); p != "" {
			if !slices.Contains(plan.AppendPathDirs, p) {
				plan.AppendPathDirs = append(plan.AppendPathDirs, p)
			}
		}
	}

	if !slices.Contains([]string{"transparent"}, mode) {
		for k, v := range ProxyEnv(plan.SNIDomains) {
			plan.EnvSet[k] = v
		}
	}

	dnsHosts := config.MergeStringMaps(repo.Network.DNS.Hosts, effective.Network.DNS.Hosts)
	dnsEnabled := repo.Network.DNS.Enabled || effective.Network.DNS.Enabled

	if len(plan.SNIDomains) > 0 ||
		len(plan.TCPEndpoints) > 0 ||
		dnsEnabled || len(dnsHosts) > 0 {
		rcPath := filepath.Join(plan.TmpDir, "resolv.conf")
		const resolvConf = "nameserver 127.0.0.1\noptions timeout:1 retries:1\n"
		if err := os.WriteFile(rcPath, []byte(resolvConf), 0o600); err != nil { // #nosec G703 -- keg-created dir
			return Plan{}, nil, fmt.Errorf("write resolv.conf: %w", err)
		}
		plan.ResolvConf = rcPath
		upstream := repo.Network.DNS.Upstream
		if effective.Network.DNS.Upstream != "" {
			upstream = effective.Network.DNS.Upstream
		}
		if upstream == "" {
			upstream = FirstHostNameserver()
		}
		whitelist := append([]string{}, plan.SNIDomains...)
		for _, ep := range plan.TCPEndpoints {
			whitelist = append(whitelist, strings.ToLower(ep.Host))
		}
		plan.EgressDNS = &DNSConfig{
			Hosts:     dnsHosts,
			Whitelist: whitelist,
			Upstream:  upstream,
		}
		hostsPath := filepath.Join(plan.TmpDir, "hosts")
		content := BuildHostsFile(dnsHosts)
		if err := os.WriteFile(hostsPath, []byte(content), 0o600); err != nil { // #nosec G703 -- keg-created dir
			return Plan{}, nil, fmt.Errorf("write hosts file: %w", err)
		}
		plan.HostsFile = hostsPath
	}

	if len(repo.Ports) > 0 {
		if err := AddPortsToPlan(&plan, repo.Ports); err != nil {
			return Plan{}, nil, err
		}
	}

	if len(repo.ForwardHosts) > 0 {
		plan.ForwardHosts = append(plan.ForwardHosts, repo.ForwardHosts...)
		plan.EnvSet[EnvForwardHosts] = portsfw.FormatForwardHosts(plan.ForwardHosts)
	}

	tasks := repo.DelegatedTasks
	if env := os.Getenv("RUNNER_WHITELIST"); env != "" {
		for _, name := range strings.Split(env, ",") {
			if name = strings.TrimSpace(name); name != "" {
				tasks.Exact = append(tasks.Exact, name)
			}
		}
	}
	tasks.Exact = append(tasks.Exact, effective.Runner.ExtraExact...)
	tasks.Prefixes = append(tasks.Prefixes, effective.Runner.ExtraPrefixes...)
	tasks.Raw = append(tasks.Raw, effective.Runner.ExtraRaw...)
	if len(tasks.Exact) > 0 || len(tasks.Prefixes) > 0 || len(tasks.Raw) > 0 {
		plan.DelegatedTasks = tasks
		plan.UserRunnerCfg = effective.Runner
		plan.EnableRunner = true
		plan.EnvSet[EnvDelegation] = "1"
		hooksDir := filepath.Join(instanceDir, "hooks")
		if err := os.MkdirAll(hooksDir, 0o700); err != nil { // #nosec G703 -- trusted dir
			return Plan{}, nil, fmt.Errorf("create hooks dir: %w", err)
		}
		plan.HooksDir = hooksDir
	}

	if overlay == OverlayDisk {
		storageBase := effective.Paths.StorageBase
		if storageBase == "" {
			storageBase = "/var/lib/containers/storage/sandbox"
		}
		if expanded, err := config.ExpandPath(storageBase); err == nil {
			storageBase = expanded
		}
		layer := filepath.Join(storageBase, diskName)
		for _, sub := range []string{"rw", "work"} {
			if err := os.MkdirAll(filepath.Join(layer, sub), 0o750); err != nil { // #nosec G703 -- storage_base from trusted local user config
				return Plan{}, nil, fmt.Errorf("prepare disk layer %s: %w", layer, err)
			}
		}
		plan.DiskLayerRW = filepath.Join(layer, "rw")
		plan.DiskLayerWork = filepath.Join(layer, "work")
	}

	// Inform guest Landlock about any extra writable mount destinations
	var writableMounts []string
	for _, m := range plan.Mounts {
		if m.Mode != config.MountRO && m.Dest != "" {
			if !slices.Contains(writableMounts, m.Dest) {
				writableMounts = append(writableMounts, m.Dest)
			}
		}
	}
	if len(writableMounts) > 0 {
		plan.EnvSet[EnvLandlockWritable] = strings.Join(writableMounts, ",")
	}

	return plan, user, nil
}

// StartBackgroundServices starts all configured egress, proxy, DNS, port-forwarding,
// delegation runner, and secret refresh services for a running sandbox.
func StartBackgroundServices(ctx context.Context, sb *Sandbox, plan Plan, user *config.User, auditWriter io.Writer) error {
	if sb.IsClosed() {
		return nil
	}

	aw := auditWriter
	if aw == nil {
		aw = plan.AuditWriter
	}

	// DNS channel
	if plan.EgressDNS != nil {
		dnsCfg := *plan.EgressDNS
		if aw != nil {
			dnsCfg.Audit = aw
		}
		if err := sb.StartEgressDNS(dnsCfg, plan.TCPEndpoints); err != nil {
			return fmt.Errorf("start egress dns: %w", err)
		}
	}

	// Proxy channel
	if len(plan.SNIDomains) > 0 || len(plan.TCPEndpoints) > 0 {
		proxyAudit := aw
		if proxyAudit == nil {
			proxyAudit = os.Stderr
		}
		err := sb.StartEgressProxy(EgressProxyConfig{
			SNIDomains:    plan.SNIDomains,
			UpstreamProxy: plan.UpstreamProxy,
			Audit:         proxyAudit,
		})
		if err != nil {
			return fmt.Errorf("start egress proxy: %w", err)
		}
	}

	// Port back-channel
	if len(plan.Ports) > 0 {
		if err := sb.StartPortsForward(plan.Ports); err != nil {
			return fmt.Errorf("start ports forward: %w", err)
		}
	}

	// Host port forward channel (Sandbox -> Host)
	if len(plan.ForwardHosts) > 0 {
		if err := sb.StartHostForward(plan.ForwardHosts); err != nil {
			return fmt.Errorf("start host forward: %w", err)
		}
	}

	// Delegation runner channel
	if plan.EnableRunner && (len(plan.DelegatedTasks.Exact) > 0 || len(plan.DelegatedTasks.Prefixes) > 0 || len(plan.DelegatedTasks.Raw) > 0) {
		runnerCfg := plan.UserRunnerCfg
		if user != nil && (user.Runner.JustBin != "" || len(user.Runner.ExtraExact) > 0 || len(user.Runner.ExtraPrefixes) > 0 || len(user.Runner.ExtraRaw) > 0) {
			runnerCfg = user.Runner
		}
		engine, engineErr := runner.NewEngine(plan.DelegatedTasks, runnerCfg)
		if engineErr != nil {
			return fmt.Errorf("delegation whitelist: %w", engineErr)
		}
		runnerCfgPath := plan.RepoCfgPath
		if runnerCfgPath == "" {
			runnerCfgPath = filepath.Join(plan.RepoRoot, ".keg.yaml")
		}
		serverCfg := runner.ServerConfig{
			Engine:   engine,
			RepoRoot: plan.RepoRoot,
			HooksDir: plan.HooksDir,
			ValidateTrust: func() error {
				return trust.VerifyApproved("", plan.RepoRoot, runnerCfgPath)
			},
		}
		if aw != nil {
			serverCfg.Audit = func(allowed bool, task string, reason string) {
				w := bufio.NewWriter(aw)
				verdict := "ERLAUBT"
				if !allowed {
					verdict = "BLOCKIERT"
				}
				if reason != "" && !allowed {
					_, _ = fmt.Fprintf(w, "DELEGATION %s %s: %s\n", verdict, task, reason)
				} else {
					_, _ = fmt.Fprintf(w, "DELEGATION %s %s\n", verdict, task)
				}
				_ = w.Flush()
			}
		}
		if err := sb.StartRunner(serverCfg); err != nil {
			return fmt.Errorf("start delegation runner: %w", err)
		}
	}

	// Secret background refresher
	if len(plan.SecretDir) > 0 && len(plan.Secrets) > 0 {
		sb.closeMu.Lock()
		if !sb.secretsStarted {
			sb.secretsStarted = true
			sb.closeMu.Unlock()
			refresher := secrets.NewRefresher()
			go refresher.Start(ctx, plan.Secrets, plan.SecretSources, plan.SecretDir, func(name, status string) {
				if aw != nil {
					w := bufio.NewWriter(aw)
					_, _ = fmt.Fprintf(w, "SECRET %s %s\n", name, status)
					_ = w.Flush()
				}
				slog.Info("secret refresh", "name", name, "status", status)
			}, func(err error) {
				slog.Error("secret refresh fatal error", "err", err)
				_ = sb.Signal(syscall.SIGTERM)
			}, plan.SecretTemplateCtx)
		} else {
			sb.closeMu.Unlock()
		}
	}

	return nil
}

// FirstHostNameserver returns the first nameserver from the host's /etc/resolv.conf.
func FirstHostNameserver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "127.0.0.53:53"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1]
				if !strings.Contains(ip, ":") {
					return ip + ":53"
				}
				return "[" + ip + "]:53"
			}
		}
	}
	return "127.0.0.53:53"
}

// BuildHostsFile renders a static /etc/hosts file from dns.hosts.
func BuildHostsFile(hosts map[string]string) string {
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n")
	b.WriteString("::1 localhost\n")
	for pattern, ip := range hosts {
		name := strings.TrimPrefix(pattern, "*.")
		fmt.Fprintf(&b, "%s %s\n", ip, name)
	}
	return b.String()
}

// UpstreamProxyFromEnv picks the restrictive corporate proxy from environment variables.
func UpstreamProxyFromEnv(getenv func(string) string) string {
	for _, k := range []string{
		"HTTPS_PROXY", "https_proxy",
		"HTTP_PROXY", "http_proxy",
	} {
		if v := getenv(k); v != "" {
			v = strings.TrimPrefix(v, "http://")
			v = strings.TrimPrefix(v, "https://")
			return v
		}
	}
	return ""
}

func envMap() map[string]string {
	res := map[string]string{}
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			res[parts[0]] = parts[1]
		}
	}
	return res
}

func resolveTemplates(r *config.Repo, tctx template.Context) error {
	for i := range r.Mounts {
		src, err := template.Apply(r.Mounts[i].Src, tctx)
		if err != nil {
			return fmt.Errorf("mounts[%d].src: %w", i, err)
		}
		r.Mounts[i].Src = src
		dest, err := template.Apply(r.Mounts[i].Dest, tctx)
		if err != nil {
			return fmt.Errorf("mounts[%d].dest: %w", i, err)
		}
		r.Mounts[i].Dest = dest
	}
	for k, v := range r.Env.Set {
		rendered, err := template.Apply(v, tctx)
		if err != nil {
			return fmt.Errorf("env.set[%s]: %w", k, err)
		}
		r.Env.Set[k] = rendered
	}
	for i := range r.Paths.Extra {
		rendered, err := template.Apply(r.Paths.Extra[i], tctx)
		if err != nil {
			return fmt.Errorf("paths.extra[%d]: %w", i, err)
		}
		r.Paths.Extra[i] = rendered
	}
	for i := range r.Paths.Prepend {
		rendered, err := template.Apply(r.Paths.Prepend[i], tctx)
		if err != nil {
			return fmt.Errorf("paths.prepend[%d]: %w", i, err)
		}
		r.Paths.Prepend[i] = rendered
	}
	for i := range r.Paths.Append {
		rendered, err := template.Apply(r.Paths.Append[i], tctx)
		if err != nil {
			return fmt.Errorf("paths.append[%d]: %w", i, err)
		}
		r.Paths.Append[i] = rendered
	}
	return nil
}

func resolveExtraPath(pathStr, repoRoot, sandboxHome string) string {
	pathStr = strings.TrimSpace(pathStr)
	if pathStr == "" {
		return ""
	}
	if pathStr == "~" || strings.HasPrefix(pathStr, "~/") {
		return sandboxHome + strings.TrimPrefix(pathStr, "~")
	}
	if filepath.IsAbs(pathStr) {
		return filepath.Clean(pathStr)
	}
	return filepath.Clean(filepath.Join(repoRoot, pathStr))
}

// AddPortsToPlan resolves the given port specifications and attaches them
// to the Plan, updating the environment allowlist (KEG_PORTS) and any
// named port variables (KEG_PORT_<NAME>).
func AddPortsToPlan(plan *Plan, specs []config.PortSpec) error {
	if len(specs) == 0 {
		return nil
	}
	resolved, err := portsfw.Resolve(specs, func(hostIP string) (*net.Listener, error) {
		var lc net.ListenConfig
		if hostIP == "" {
			hostIP = "127.0.0.1"
		}
		ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(hostIP, "0"))
		if err != nil {
			return nil, err
		}
		return &ln, nil
	})
	if err != nil {
		for _, p := range resolved {
			if p.Listener != nil {
				_ = p.Listener.Close()
			}
		}
		return fmt.Errorf("resolve ports: %w", err)
	}
	plan.Ports = append(plan.Ports, resolved...)
	if plan.EnvSet == nil {
		plan.EnvSet = make(map[string]string)
	}
	for k, v := range portsfw.PortEnv(resolved) {
		plan.EnvSet[k] = v
	}
	plan.EnvSet[EnvPortsForward] = portsfw.FormatAllowed(plan.Ports)
	return nil
}
