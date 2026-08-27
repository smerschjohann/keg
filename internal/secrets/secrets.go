// Package secrets implements the host-side secret source fetch and periodic
// refresher mechanism for /run/secrets bind mounting (CONCEPT.md §4.7).
package secrets

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/template"
)

// FetchInitial runs the source command for each requested secret once and writes
// the output atomically to destDir/<name> with mode 0400 (destDir with mode 0700).
func FetchInitial(ctx context.Context, requested []config.SecretRef, sources map[string]config.SecretSource, destDir string, tctx ...template.Context) error {
	if len(requested) == 0 {
		return nil
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("create secret dir %s: %w", destDir, err)
	}

	var baseCtx template.Context
	if len(tctx) > 0 {
		baseCtx = tctx[0]
	}

	for _, ref := range requested {
		source, ok := sources[ref.Name]
		if !ok {
			return fmt.Errorf("secret %q requested by repository is not defined in secret_sources (user config)", ref.Name)
		}
		if source.Async {
			continue
		}
		if len(source.Cmd) == 0 {
			return fmt.Errorf("secret %q has empty command", ref.Name)
		}
		sctx := buildSecretContext(ref, baseCtx)
		renderedCmd, err := renderCmd(source.Cmd, sctx)
		if err != nil {
			return fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		timeout := source.Timeout.Duration
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		data, err := runCmd(fetchCtx, renderedCmd, buildSubprocessEnv(sctx))
		cancel()
		if err != nil {
			return fmt.Errorf("initial fetch of secret %q: %w", ref.Name, err)
		}
		if err := writeAtomic(destDir, ref.Name, data); err != nil {
			return fmt.Errorf("write secret %q: %w", ref.Name, err)
		}
	}
	return nil
}

func buildSecretContext(ref config.SecretRef, baseCtx template.Context) template.Context {
	vars := make(map[string]string, len(baseCtx.Vars)+1)
	maps.Copy(vars, baseCtx.Vars)
	vars["secret_name"] = ref.Name
	return template.Context{
		Vars: vars,
		Env:  baseCtx.Env,
	}
}

func renderCmd(cmd []string, sctx template.Context) ([]string, error) {
	out := make([]string, len(cmd))
	for i, arg := range cmd {
		rendered, err := template.Apply(arg, sctx)
		if err != nil {
			return nil, fmt.Errorf("render command argument %q: %w", arg, err)
		}
		out[i] = rendered
	}
	return out, nil
}

func buildSubprocessEnv(sctx template.Context) []string {
	var extra []string
	if inst, ok := sctx.Vars["instance"]; ok && inst != "" {
		extra = append(extra, "KEG_INSTANCE="+inst)
	}
	if sec, ok := sctx.Vars["secret_name"]; ok && sec != "" {
		extra = append(extra, "KEG_SECRET_NAME="+sec)
	}
	if rd, ok := sctx.Vars["repo_dir"]; ok && rd != "" {
		extra = append(extra, "KEG_REPO_DIR="+rd)
	}
	return extra
}

func runCmd(ctx context.Context, cmd []string, extraEnv []string) ([]byte, error) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...) // #nosec G204 -- cmd from trusted user config secret_sources
	if len(extraEnv) > 0 {
		c.Env = append(os.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o400); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	destPath := filepath.Join(dir, name)
	return os.Rename(tmpName, destPath)
}

// Refresher coordinates periodic background refreshes of dynamic secrets.
type Refresher struct{}

// NewRefresher creates a Refresher instance.
func NewRefresher() *Refresher {
	return &Refresher{}
}

// Start launches a refresher goroutine for each dynamic secret (interval > 0 or async)
// and blocks until ctx is canceled or a fatal error occurs.
func (r *Refresher) Start(ctx context.Context, requested []config.SecretRef, sources map[string]config.SecretSource, destDir string, audit func(name, status string), onFatalError func(err error), tctx ...template.Context) {
	var baseCtx template.Context
	if len(tctx) > 0 {
		baseCtx = tctx[0]
	}

	var wg sync.WaitGroup
	for _, ref := range requested {
		source, ok := sources[ref.Name]
		if !ok || (source.Interval.Duration <= 0 && !source.Async) {
			continue
		}
		wg.Add(1)
		go func(ref config.SecretRef, src config.SecretSource) {
			defer wg.Done()
			name := ref.Name
			sctx := buildSecretContext(ref, baseCtx)

			doFetch := func() error {
				renderedCmd, err := renderCmd(src.Cmd, sctx)
				if err != nil {
					if audit != nil {
						audit(name, "error")
					}
					if src.OnRefreshError == "fail" {
						if onFatalError != nil {
							onFatalError(fmt.Errorf("render secret %q cmd: %w", name, err))
						}
						return err
					}
					return nil
				}
				timeout := src.Timeout.Duration
				if timeout <= 0 {
					timeout = 10 * time.Second
				}
				fetchCtx, cancel := context.WithTimeout(ctx, timeout)
				newData, err := runCmd(fetchCtx, renderedCmd, buildSubprocessEnv(sctx))
				cancel()
				if err != nil {
					if audit != nil {
						audit(name, "error")
					}
					if src.OnRefreshError == "fail" {
						if onFatalError != nil {
							onFatalError(fmt.Errorf("fetch secret %q: %w", name, err))
						}
						return err
					}
					return nil
				}

				curPath := filepath.Join(destDir, name)
				curData, readErr := os.ReadFile(curPath) // #nosec G304 -- internal secret dir
				if readErr == nil && bytes.Equal(curData, newData) {
					if audit != nil {
						audit(name, "unchanged")
					}
					return nil
				}

				if writeErr := writeAtomic(destDir, name, newData); writeErr != nil {
					if audit != nil {
						audit(name, "error")
					}
					if src.OnRefreshError == "fail" {
						if onFatalError != nil {
							onFatalError(fmt.Errorf("write secret %q: %w", name, writeErr))
						}
						return writeErr
					}
				} else {
					if audit != nil {
						audit(name, "changed")
					}
				}
				return nil
			}

			if src.Async {
				if err := doFetch(); err != nil && src.OnRefreshError == "fail" {
					return
				}
			}

			if src.Interval.Duration <= 0 {
				return
			}

			ticker := time.NewTicker(src.Interval.Duration)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := doFetch(); err != nil && src.OnRefreshError == "fail" {
						return
					}
				}
			}
		}(ref, source)
	}
	wg.Wait()
}
