package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/runner"

	"github.com/urfave/cli/v3"
)

// delegateAction runs one job on the host via delegation channel C and
// returns the process exit code for the sandbox shell: the job's own code,
// 126 when the whitelist declines, 125 on protocol errors, 127 when no
// runner is reachable (CONCEPT.md §4.5, AGENTS.md §5).
func delegateAction(argv []string) int {
	return delegateActionWithIO(argv, "", "", "", os.Stdout, os.Stderr)
}

func delegateActionWithIO(argv []string, repoDir, repoCfgPath, userCfgPath string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: keg delegate [--list [--json]] <task|cmd> [args…]")
		return 2
	}
	if listReq, jsonOut, parsedRepo, parsedCfg, parsedUserCfg, ok := parseDelegateListFlags(argv); ok && listReq {
		if parsedRepo != "" {
			repoDir = parsedRepo
		}
		if parsedCfg != "" {
			repoCfgPath = parsedCfg
		}
		if parsedUserCfg != "" {
			userCfgPath = parsedUserCfg
		}
		return delegateList(repoDir, repoCfgPath, userCfgPath, jsonOut, stdout, stderr)
	}

	conn, err := runner.Dial()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "keg delegate: %v\n", err)
		return runner.CodeNoRunner
	}
	return runner.Exec(conn, argv, "", stdout, stderr)
}

func parseDelegateListFlags(argv []string) (list, jsonOut bool, repoDir, repoCfg, userCfg string, ok bool) {
	if len(argv) == 0 {
		return false, false, "", "", "", false
	}
	first := argv[0]
	if first != "--list" && first != "-l" && first != "--json" {
		return false, false, "", "", "", false
	}
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--list", "-l":
			list = true
		case "--json":
			jsonOut = true
		case "--repo":
			if i+1 >= len(argv) {
				return false, false, "", "", "", false
			}
			repoDir = argv[i+1]
			i++
		case "--config", "-c":
			if i+1 >= len(argv) {
				return false, false, "", "", "", false
			}
			repoCfg = argv[i+1]
			i++
		case "--user-config":
			if i+1 >= len(argv) {
				return false, false, "", "", "", false
			}
			userCfg = argv[i+1]
			i++
		default:
			return false, false, "", "", "", false
		}
	}
	return list, jsonOut, repoDir, repoCfg, userCfg, list
}

func delegateList(repoDir, repoCfgPath, userCfgPath string, jsonOut bool, stdout, stderr io.Writer) int {
	var tasks []runner.TaskInfo
	if conn, err := runner.Dial(); err == nil {
		t, listErr := runner.List(conn)
		if listErr != nil {
			_, _ = fmt.Fprintf(stderr, "keg delegate --list: %v\n", listErr)
			return runner.CodeProtocolError
		}
		tasks = t
	} else {
		t, hostErr := loadHostDelegatedTasks(repoDir, repoCfgPath, userCfgPath)
		if hostErr != nil {
			_, _ = fmt.Fprintf(stderr, "keg delegate --list: %v\n", hostErr)
			return 1
		}
		tasks = t
	}

	if jsonOut {
		if tasks == nil {
			tasks = []runner.TaskInfo{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(tasks); err != nil {
			_, _ = fmt.Fprintf(stderr, "keg delegate --list: %v\n", err)
			return 1
		}
		return 0
	}
	_, _ = io.WriteString(stdout, runner.FormatTaskList(tasks))
	return 0
}

func loadHostDelegatedTasks(repoDir, repoCfgPath, userCfgPath string) ([]runner.TaskInfo, error) {
	root := repoDir
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("determine repo dir: %w", err)
		}
		root = wd
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	cfgPath := repoCfgPath
	if cfgPath == "" {
		cfgPath = filepath.Join(root, ".keg.yaml")
	}
	repo, err := config.LoadRepo(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && repoCfgPath == "" {
			repo = &config.Repo{Version: config.SupportedVersion}
		} else {
			return nil, err
		}
	}

	user := &config.User{}
	userPath := userCfgPath
	if userPath == "" {
		userPath = config.DefaultUserPath()
	}
	if data, err := os.ReadFile(userPath); err == nil { // #nosec G304 -- user config path
		parsed, parseErr := config.ParseUser(data)
		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", userPath, parseErr)
		}
		user = parsed
	} else if userCfgPath != "" {
		return nil, fmt.Errorf("load user config: %w", err)
	}

	effective := config.MatchRepo(user, root)
	engine, err := runner.NewEngine(repo.DelegatedTasks, effective.Runner)
	if err != nil {
		return nil, err
	}
	engine.SetFallbackDescriptions(config.DiscoverJustfileDescriptions(root))
	return engine.Rules(), nil
}

// delegateCommand wires the subcommand. os.Exit here is intentional for
// job execution: the exit code IS the contract with `just delegate` recipes.
func delegateCommand() *cli.Command {
	return &cli.Command{
		Name:            "delegate",
		Usage:           "run a whitelisted task on the HOST outside the sandbox (or --list allowed tasks)",
		SkipFlagParsing: true,
		Description: "Runs inside the sandbox (or lists allowed tasks with --list).\n" +
			"Examples:\n" +
			"  keg delegate --list\n" +
			"  keg delegate --list --json\n" +
			"  if [ \"{{in_sandbox}}\" = \"1\" ]; then just delegate container-build; fi",
		Action: func(_ context.Context, c *cli.Command) error {
			argv := c.Args().Slice()
			if list, _, _, _, _, ok := parseDelegateListFlags(argv); ok && list {
				out := c.Root().Writer
				if out == nil {
					out = os.Stdout
				}
				errOut := c.Root().ErrWriter
				if errOut == nil {
					errOut = os.Stderr
				}
				code := delegateActionWithIO(argv, "", c.String("config"), c.String("user-config"), out, errOut)
				if code != 0 {
					return cli.Exit("", code)
				}
				return nil
			}
			os.Exit(delegateAction(argv))
			return nil
		},
	}
}
