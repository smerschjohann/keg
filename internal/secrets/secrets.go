// Package secrets implements the host-side secret source fetch and periodic
// refresher mechanism for /run/secrets bind mounting (CONCEPT.md §4.7).
package secrets

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/smerschjohann/keg/internal/config"
)

// FetchInitial runs the source command for each requested secret once and writes
// the output atomically to destDir/<name> with mode 0400 (destDir with mode 0700).
func FetchInitial(ctx context.Context, requested []config.SecretRef, sources map[string]config.SecretSource, destDir string) error {
	if len(requested) == 0 {
		return nil
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("create secret dir %s: %w", destDir, err)
	}

	for _, ref := range requested {
		source, ok := sources[ref.Name]
		if !ok {
			return fmt.Errorf("secret %q requested by repository is not defined in secret_sources (user config)", ref.Name)
		}
		if len(source.Cmd) == 0 {
			return fmt.Errorf("secret %q has empty command", ref.Name)
		}
		timeout := source.Timeout.Duration
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		data, err := runCmd(fetchCtx, source.Cmd)
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

func runCmd(ctx context.Context, cmd []string) ([]byte, error) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...) // #nosec G204 -- cmd from trusted user config secret_sources
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

// Start launches a refresher goroutine for each dynamic secret (interval > 0)
// and blocks until ctx is canceled or a fatal error occurs.
func (r *Refresher) Start(ctx context.Context, requested []config.SecretRef, sources map[string]config.SecretSource, destDir string, audit func(name, status string), onFatalError func(err error)) {
	var wg sync.WaitGroup
	for _, ref := range requested {
		source, ok := sources[ref.Name]
		if !ok || source.Interval.Duration <= 0 {
			continue
		}
		wg.Add(1)
		go func(name string, src config.SecretSource) {
			defer wg.Done()
			ticker := time.NewTicker(src.Interval.Duration)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					timeout := src.Timeout.Duration
					if timeout <= 0 {
						timeout = 10 * time.Second
					}
					fetchCtx, cancel := context.WithTimeout(ctx, timeout)
					newData, err := runCmd(fetchCtx, src.Cmd)
					cancel()
					if err != nil {
						if audit != nil {
							audit(name, "error")
						}
						if src.OnRefreshError == "fail" {
							if onFatalError != nil {
								onFatalError(fmt.Errorf("refresh secret %q: %w", name, err))
							}
							return
						}
						continue
					}

					curPath := filepath.Join(destDir, name)
					curData, readErr := os.ReadFile(curPath) // #nosec G304 -- internal secret dir
					if readErr == nil && bytes.Equal(curData, newData) {
						if audit != nil {
							audit(name, "unchanged")
						}
						continue
					}

					if writeErr := writeAtomic(destDir, name, newData); writeErr != nil {
						if audit != nil {
							audit(name, "error")
						}
						if src.OnRefreshError == "fail" {
							if onFatalError != nil {
								onFatalError(fmt.Errorf("write refreshed secret %q: %w", name, writeErr))
							}
							return
						}
					} else {
						if audit != nil {
							audit(name, "changed")
						}
					}
				}
			}
		}(ref.Name, source)
	}
	wg.Wait()
}
