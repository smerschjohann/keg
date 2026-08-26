package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/portsfw"
	"github.com/smerschjohann/keg/internal/runner"
	"github.com/smerschjohann/keg/internal/template"
)

// buildRunPlan loads and validates all configuration for a sandbox run and
// produces the orchestrator plan. It performs no process management —
// Launch owns that. Errors name the offending file/field.
func buildRunPlan(repoDir, repoCfgPath, userCfgPath string, overlay orchestrator.Overlay, diskName string, cacheOverlay orchestrator.Overlay, isolatedCacheName string) (orchestrator.Plan, error) {
	root := repoDir
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	// Repo config: explicit path or <root>/.keg.yaml (required).
	cfgPath := repoCfgPath
	if cfgPath == "" {
		cfgPath = filepath.Join(root, ".keg.yaml")
	}
	repo, err := config.LoadRepo(cfgPath)
	if err != nil {
		return orchestrator.Plan{}, fmt.Errorf("repo %s: %w (create a .keg.yaml or pass --config)", root, err)
	}

	// User config: optional.
	user := &config.User{}
	userPath := userCfgPath
	if userPath == "" {
		userPath = config.DefaultUserPath()
	}
	if data, err := os.ReadFile(userPath); err == nil { // #nosec G304 -- user-controlled config path by design
		parsed, parseErr := config.ParseUser(data)
		if parseErr != nil {
			return orchestrator.Plan{}, fmt.Errorf("%s: %w", userPath, parseErr)
		}
		user = parsed
	} else if userCfgPath != "" {
		// An explicitly requested user config must exist; the default may not.
		return orchestrator.Plan{}, fmt.Errorf("load user config: %w", err)
	}

	effective := config.MatchRepo(user, root)
	vars := config.MergeVars(repo.Vars, effective.Vars, nil)

	// Template context: .Vars always, .Env only when the user config opts
	// in (THREAT_MODEL §8: host environment is never implicitly exposed).
	tctx := template.Context{Vars: vars}
	if effective.TemplateEnv.AllowEnv != nil && *effective.TemplateEnv.AllowEnv {
		tctx.Env = envMap()
	}
	if err := resolveTemplates(repo, tctx); err != nil {
		return orchestrator.Plan{}, err
	}

	plan := orchestrator.Plan{
		RepoRoot:    root,
		SandboxHome: "/home/sandbox",
		Mounts:      repo.Mounts,
		EnvUnset:    repo.Env.Unset,
		EnvSet:      map[string]string{},
		BwrapArgs:   repo.BwrapArgs,
		AllowWeakBwrap: effective.Security.AllowWeakBwrap != nil &&
			*effective.Security.AllowWeakBwrap,
		Overlay:      overlay,
		SNIDomains:   repo.Network.SNIDomains,
		TCPEndpoints: repo.Network.TCPEndpoints,
		Transparent:  repo.Network.Mode == "transparent",
	}
	for k, v := range repo.Env.Set {
		plan.EnvSet[k] = v
	}

	// Language templates (CONCEPT.md §4.6) are additive building blocks:
	// their env defaults go in first so explicit repo env.set values win;
	// cache mounts join the user mounts (tilde sources are expanded by
	// BuildArgs' caller like any other mount).
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
			return orchestrator.Plan{}, fmt.Errorf("templates: %w", terr)
		}
		for _, m := range tplMounts {
			src := m.Src
			if expanded, expErr := config.ExpandPath(src); expErr == nil {
				src = expanded
			}
			mount := config.Mount{Src: src, Dest: m.Dest, Mode: m.Mode}
			if cacheOverlay == orchestrator.OverlayEphemeral {
				mount.Mode = config.MountEphemeral
			} else if cacheOverlay == orchestrator.OverlayDisk && isolatedCacheName != "" {
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
					if mkErr := os.MkdirAll(sub, 0o750); mkErr != nil { // #nosec G703 -- storage_base from trusted local user config
						return orchestrator.Plan{}, fmt.Errorf("prepare cache layer %s: %w", cacheDir, mkErr)
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
		// GOROOT outside /usr is invisible to the sandbox — ro-bind it at
		// its own path and put the toolchain binaries on PATH.
		if tc.GoRootNeedsBind() {
			plan.Mounts = append(plan.Mounts, config.Mount{Src: tc.GoRoot, Dest: tc.GoRoot, Mode: config.MountRO})
			plan.ExtraPathDirs = []string{tc.GoRoot + "/bin"}
		}
	}
	// Explicit-proxy vars only make sense in proxy mode; transparent mode
	// intercepts at the network layer instead.
	if repo.Network.Mode != "transparent" {
		for k, v := range orchestrator.ProxyEnv(repo.Network.SNIDomains) {
			plan.EnvSet[k] = v
		}
	}

	// DNS channel: active whenever any egress feature is configured
	// (allowed_domains, explicit enable, hosts mappings or tcp_endpoints).
	// Filtered DNS without proxy makes no sense and vice versa — the
	// resolver shares the whitelist (CONCEPT.md §4.4). tcp_endpoints names
	// join the whitelist: their A answers feed the IP correlation table.
	if len(repo.Network.SNIDomains) > 0 ||
		len(repo.Network.TCPEndpoints) > 0 ||
		repo.Network.DNS.Enabled || len(repo.Network.DNS.Hosts) > 0 {
		// The netns stage serves the filtering resolver on loopback :53
		// inside the sandbox namespace, so the classic resolv.conf works
		// again (WP-M3 Umsetzungsnotiz 1).
		rcPath := filepath.Join(plan.TmpDir, "resolv.conf")
		const resolvConf = "nameserver 127.0.0.1\noptions timeout:1 retries:1\n"
		// #nosec G304 -- path from our own instance dir
		if err := os.WriteFile(rcPath, []byte(resolvConf), 0o600); err != nil { // #nosec G703 -- keg-created dir
			return orchestrator.Plan{}, fmt.Errorf("write resolv.conf: %w", err)
		}
		plan.ResolvConf = rcPath
		upstream := repo.Network.DNS.Upstream
		if upstream == "" {
			// Default to the host resolver: in the target environment the
			// only reachable DNS is kube-dns (cluster.local names); there
			// is no public fallback.
			upstream = firstHostNameserver()
		}
		whitelist := append([]string{}, repo.Network.SNIDomains...)
		for _, ep := range repo.Network.TCPEndpoints {
			whitelist = append(whitelist, strings.ToLower(ep.Host))
		}
		plan.EgressDNS = &orchestrator.DNSConfig{
			Hosts:     repo.Network.DNS.Hosts,
			Whitelist: whitelist,
			Upstream:  upstream,
		}
		hostsPath := filepath.Join(plan.TmpDir, "hosts")
		content := buildHostsFile(repo.Network.DNS.Hosts)
		// #nosec G304 -- path from our own instance dir
		if err := os.WriteFile(hostsPath, []byte(content), 0o600); err != nil { // #nosec G703 -- keg-created dir
			return orchestrator.Plan{}, fmt.Errorf("write hosts file: %w", err)
		}
		plan.HostsFile = hostsPath
	}

	// Port back-channel (Kanal E): resolve entries and reserve dynamic host
	// ports up front — the binding IS the reservation, so nothing can steal
	// the port between planning and serving. Named entries are exported to
	// the sandbox as KEG_PORT_<NAME>; the guest forwarder gets the
	// target allowlist via KEG_PORTS (deny-by-default).
	if len(repo.Ports) > 0 {
		resolved, err := portsfw.Resolve(repo.Ports, func() (*net.Listener, error) {
			var lc net.ListenConfig
			ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return &ln, nil
		})
		if err != nil {
			closePortListeners(resolved)
			return orchestrator.Plan{}, fmt.Errorf("resolve ports: %w", err)
		}
		plan.Ports = resolved
		for k, v := range portsfw.PortEnv(resolved) {
			plan.EnvSet[k] = v
		}
		plan.EnvSet[orchestrator.EnvPortsForward] = portsfw.FormatAllowed(resolved)
	}

	// Prepare host-side directories per overlay mode.
	tmpBase := effective.Paths.TmpBase
	if expanded, err := config.ExpandPath(tmpBase); err == nil && expanded != "" {
		tmpBase = expanded
	} else {
		tmpBase = os.TempDir()
	}
	instanceDir := ""
	if tmpBase != "" {
		// tmpBase originates from the user config; honoring machine-local
		// paths is keg's core function, traversal is not a threat here.
		if err := os.MkdirAll(tmpBase, 0o750); err == nil { // #nosec G703 -- path from trusted local user config

			if d, mkErr := os.MkdirTemp(tmpBase, "keg-"); mkErr == nil {
				instanceDir = d
			}
		}
	}
	if instanceDir == "" {
		d, err2 := os.MkdirTemp("", "keg-")
		if err2 != nil {
			return orchestrator.Plan{}, fmt.Errorf("create instance dir: %w", err2)
		}
		instanceDir = d
	}
	plan.TmpDir = instanceDir

	// Delegation channel (Kanal C): carry the repo whitelist into the plan,
	// export the guest marker and prepare the empty hooks dir used to
	// suppress host git hooks in delegated jobs (THREAT_MODEL §5.4).
	// RUNNER_WHITELIST keeps the bestand's env override: comma-separated
	// exact task names on top of the repo config.
	tasks := repo.DelegatedTasks
	if env := os.Getenv("RUNNER_WHITELIST"); env != "" {
		for _, name := range strings.Split(env, ",") {
			if name = strings.TrimSpace(name); name != "" {
				tasks.Exact = append(tasks.Exact, name)
			}
		}
	}
	// User-config extras union with the repo rules (CONCEPT.md §5): a
	// machine may allow MORE locally, never less.
	tasks.Exact = append(tasks.Exact, effective.Runner.ExtraExact...)
	tasks.Prefixes = append(tasks.Prefixes, effective.Runner.ExtraPrefixes...)
	tasks.Raw = append(tasks.Raw, effective.Runner.ExtraRaw...)
	if len(tasks.Exact) > 0 || len(tasks.Prefixes) > 0 || len(tasks.Raw) > 0 {
		plan.DelegatedTasks = tasks
		plan.EnableRunner = true
		plan.EnvSet[orchestrator.EnvDelegation] = "1"
		hooksDir := filepath.Join(instanceDir, "hooks")
		// #nosec G703 -- hooksDir derives from the instance temp dir created above
		if err := os.MkdirAll(hooksDir, 0o700); err != nil {
			return orchestrator.Plan{}, fmt.Errorf("create hooks dir: %w", err)
		}
		plan.HooksDir = hooksDir
	}

	if overlay == orchestrator.OverlayDisk {
		storageBase := effective.Paths.StorageBase
		if storageBase == "" {
			storageBase = "/var/lib/containers/storage/sandbox"
		}
		if expanded, err := config.ExpandPath(storageBase); err == nil {
			storageBase = expanded
		}
		layer := filepath.Join(storageBase, diskName)
		for _, sub := range []string{"rw", "work"} {
			// layer dir from trusted local user config (storage_base)
			if err := os.MkdirAll(filepath.Join(layer, sub), 0o750); err != nil { // #nosec G703 -- storage_base from trusted local user config

				return orchestrator.Plan{}, fmt.Errorf("prepare disk layer %s: %w", layer, err)
			}
		}
		plan.DiskLayerRW = filepath.Join(layer, "rw")
		plan.DiskLayerWork = filepath.Join(layer, "work")
	}

	return plan, nil
}

// closePortListeners releases the pre-bound channel-E reservations when
// plan building fails after allocation.
func closePortListeners(ports []portsfw.ResolvedPort) {
	for _, p := range ports {
		if p.Listener != nil {
			_ = p.Listener.Close()
		}
	}
}

// runAction implements `keg run [--] <cmd…>`: build the plan, launch
// bwrap into the reexec guest, forward signals, wait and mirror the exit
// code.
func runAction(ctx context.Context, c *cliCommand) error {
	repoDir := c.String("repo")
	if repoDir == "" {
		var err error
		repoDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("determine repo dir: %w", err)
		}
	}

	overlay := orchestrator.OverlayPlain
	diskName := c.String("disk-overlay")
	switch {
	case c.Bool("ephemeral") && diskName != "":
		return fmt.Errorf("--ephemeral and --disk-overlay are mutually exclusive")
	case c.Bool("ephemeral"):
		overlay = orchestrator.OverlayEphemeral
	case diskName != "":
		overlay = orchestrator.OverlayDisk
	}

	cacheOverlay := orchestrator.OverlayPlain
	isolatedCacheName := c.String("isolated-cache-name")
	switch {
	case c.Bool("isolate-caches") && isolatedCacheName != "":
		return fmt.Errorf("--isolate-caches and --isolated-cache-name are mutually exclusive")
	case c.Bool("isolate-caches"):
		cacheOverlay = orchestrator.OverlayEphemeral
	case isolatedCacheName != "":
		cacheOverlay = orchestrator.OverlayDisk
	}

	plan, err := buildRunPlan(repoDir, c.String("config"), c.String("user-config"), overlay, diskName, cacheOverlay, isolatedCacheName)
	if err != nil {
		return err
	}
	plan.Command = c.Args().Slice()
	if len(plan.Command) == 0 {
		plan.Command = []string{"/bin/bash", "-i"}
	}

	sb, err := orchestrator.Launch(ctx, plan)
	if err != nil {
		return err
	}
	defer sb.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = sb.Signal(sig)
		}
	}()

	// Serve egress channel A while the sandbox runs; closing the sandbox
	// tears the session down (THREAT_MODEL §8.1: only controlled channels).
	if plan.EgressDNS != nil {
		if err := sb.StartEgressDNS(*plan.EgressDNS, plan.TCPEndpoints); err != nil {
			fmt.Fprintf(os.Stderr, "keg: egress dns: %v\n", err)
		}
	}
	if len(plan.SNIDomains) > 0 || len(plan.TCPEndpoints) > 0 {
		err := sb.StartEgressProxy(orchestrator.EgressProxyConfig{
			SNIDomains:    plan.SNIDomains,
			UpstreamProxy: upstreamProxyFromEnv(os.Getenv),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "keg: egress proxy: %v\n", err)
		}
	}

	// Port back-channel: listeners were reserved during plan building;
	// serving starts now and ends with Sandbox.Close.
	if len(plan.Ports) > 0 {
		if err := sb.StartPortsForward(plan.Ports); err != nil {
			fmt.Fprintf(os.Stderr, "keg: ports forward: %v\n", err)
		}
	}

	// Delegation channel (Kanal C): the whitelist engine is validated here
	// so a broken config still fails fast, before any workload starts.
	if plan.EnableRunner {
		engine, engineErr := runner.NewEngine(plan.DelegatedTasks, config.RunnerCfg{})
		if engineErr != nil {
			return fmt.Errorf("delegation whitelist: %w", engineErr)
		}
		if err := sb.StartRunner(runner.ServerConfig{
			Engine:   engine,
			RepoRoot: plan.RepoRoot,
			HooksDir: plan.HooksDir,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "keg: delegation runner: %v\n", err)
		}
	}

	code, err := sb.Wait()
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// upstreamProxyFromEnv picks the restrictive corporate proxy from the HOST
// environment (CONCEPT.md §4.2: allowed targets dial via upstream, the
// rest never leave the whitelist). Returns "host:port" or "" for direct.
func upstreamProxyFromEnv(getenv func(string) string) string {
	for _, k := range []string{
		"HTTPS_PROXY", "https_proxy",
		"HTTP_PROXY", "http_proxy",
		"ALL_PROXY", "all_proxy",
	} {
		if v := getenv(k); v != "" {
			return stripProxyScheme(v)
		}
	}
	return ""
}

// stripProxyScheme removes a leading http(s):// so net.Dial accepts it.
func stripProxyScheme(v string) string {
	for _, p := range []string{"http://", "https://"} {
		if len(v) >= len(p) && v[:len(p)] == p {
			return v[len(p):]
		}
	}
	return v
}

// buildHostsFile renders static dns.hosts mappings as an /etc/hosts file.
// Wildcard patterns ("*.svc.local.test") are emitted literally per IP line;
// glibc matches exact names only, so each pattern also gets its wildcard
// form commented for documentation purposes.
func buildHostsFile(hosts map[string]string) string {
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n")
	b.WriteString("::1 localhost\n")
	for pattern, ip := range hosts {
		name := strings.TrimPrefix(pattern, "*.")
		fmt.Fprintf(&b, "%s %s\n", ip, name)
	}
	return b.String()
}

// firstHostNameserver returns the first nameserver from the host's
// /etc/resolv.conf, or "" when unreadable (fail-closed SERVFAIL).
func firstHostNameserver() string {
	data, err := os.ReadFile("/etc/resolv.conf") // #nosec G304 -- fixed host path
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		}
	}
	return ""
}

// envMap snapshots the host environment for template access.
func envMap() map[string]string {
	env := make(map[string]string, len(os.Environ()))
	for _, entry := range os.Environ() {
		if k, v, ok := strings.Cut(entry, "="); ok {
			env[k] = v
		}
	}
	return env
}

// resolveTemplates applies the restricted template language to every
// declared-template-bare field (CONCEPT.md §4.6): mount paths,
// dns.hosts targets, env.set values and port names. Everything else
// stays literal by construction — delegation rules can never be bent
// through templates.
func resolveTemplates(repo *config.Repo, tctx template.Context) error {
	for i := range repo.Mounts {
		src, err := template.Apply(repo.Mounts[i].Src, tctx)
		if err != nil {
			return fmt.Errorf("mounts[%d].src: %w", i, err)
		}
		repo.Mounts[i].Src = src
		dst, err := template.Apply(repo.Mounts[i].Dest, tctx)
		if err != nil {
			return fmt.Errorf("mounts[%d].dest: %w", i, err)
		}
		repo.Mounts[i].Dest = dst
	}
	for name, target := range repo.Network.DNS.Hosts {
		resolved, err := template.Apply(target, tctx)
		if err != nil {
			return fmt.Errorf("network.dns.hosts[%s]: %w", name, err)
		}
		repo.Network.DNS.Hosts[name] = resolved
	}
	for key, value := range repo.Env.Set {
		resolved, err := template.Apply(value, tctx)
		if err != nil {
			return fmt.Errorf("env.set[%s]: %w", key, err)
		}
		repo.Env.Set[key] = resolved
	}
	for i := range repo.Ports {
		name, err := template.Apply(repo.Ports[i].Name, tctx)
		if err != nil {
			return fmt.Errorf("ports[%d].name: %w", i, err)
		}
		repo.Ports[i].Name = name
	}
	return nil
}
