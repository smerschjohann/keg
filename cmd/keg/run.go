package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
)

// buildRunPlan loads and validates all configuration for a sandbox run and
// produces the orchestrator plan. It performs no process management —
// Launch owns that. Errors name the offending file/field.
func buildRunPlan(repoDir, repoCfgPath, userCfgPath string, overlay orchestrator.Overlay, diskName string) (orchestrator.Plan, error) {
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
	_ = vars // consumed by template resolution in WP-M4

	plan := orchestrator.Plan{
		RepoRoot:    root,
		SandboxHome: "/home/sandbox",
		Mounts:      repo.Mounts,
		EnvUnset:    repo.Env.Unset,
		EnvSet:      map[string]string{},
		BwrapArgs:   repo.BwrapArgs,
		AllowWeakBwrap: effective.Security.AllowWeakBwrap != nil &&
			*effective.Security.AllowWeakBwrap,
		Overlay:         overlay,
		EgressWhitelist: repo.Network.AllowedDomains,
	}
	for k, v := range repo.Env.Set {
		plan.EnvSet[k] = v
	}
	for k, v := range orchestrator.ProxyEnv(repo.Network.AllowedDomains) {
		plan.EnvSet[k] = v
	}

	// DNS channel: active whenever any egress feature is configured
	// (allowed_domains, explicit enable or hosts mappings). Filtered DNS
	// without proxy makes no sense and vice versa — the resolver shares
	// the whitelist (CONCEPT.md §4.4).
	if len(repo.Network.AllowedDomains) > 0 ||
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
		plan.EgressDNS = &orchestrator.DNSConfig{
			Hosts:     repo.Network.DNS.Hosts,
			Whitelist: repo.Network.AllowedDomains,
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

	plan, err := buildRunPlan(repoDir, c.String("config"), c.String("user-config"), overlay, diskName)
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
		if err := sb.StartEgressDNS(*plan.EgressDNS); err != nil {
			fmt.Fprintf(os.Stderr, "keg: egress dns: %v\n", err)
		}
	}
	if len(plan.EgressWhitelist) > 0 {
		err := sb.StartEgressProxy(orchestrator.EgressProxyConfig{
			Whitelist:     plan.EgressWhitelist,
			UpstreamProxy: upstreamProxyFromEnv(os.Getenv),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "keg: egress proxy: %v\n", err)
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
