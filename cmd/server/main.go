// Command server runs the AI Reconnaissance Platform's HTTP API server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ai-recon-platform/internal/application"
	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/logging"
	"ai-recon-platform/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	logger := logging.New(logging.Options{
		Level:  cfg.Logging.Level,
		Format: logging.Format(cfg.Logging.Format),
	})

	info := version.Get()
	logger.Info("starting_server",
		"version", info.Version,
		"commit", info.Commit,
		"environment", cfg.Application.Environment,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := application.New(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("initializing application: %w", err)
	}
	defer app.Close()

	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("running application: %w", err)
	}

	return nil
}
