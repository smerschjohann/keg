package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/smerschjohann/keg/internal/daemon"

	"github.com/urfave/cli/v3"
)

func serveAction(ctx context.Context, c *cli.Command) error {
	if c.Bool("verbose") {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	}

	cfg := daemon.Config{
		ListenAddr:   c.String("listen"),
		Auth:         c.String("auth"),
		Token:        c.String("token"),
		MaxSandboxes: c.Int("max-sandboxes"),
	}

	srv, err := daemon.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("init daemon server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-serveCtx.Done():
		}
	}()

	slog.Info("keg daemon listening", "addr", cfg.ListenAddr, "auth", cfg.Auth)
	return srv.Serve(serveCtx)
}
