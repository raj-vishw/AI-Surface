// Command worker is the background job worker process.
//
// Phase 1 verifies its required infrastructure (PostgreSQL, Redis) at
// startup and periodically thereafter, and shuts down gracefully. It does
// not yet consume jobs from a queue — that (Redis-backed queue, task
// dispatch) is introduced in a later phase; wiring it in now would be
// functionality this phase explicitly defers. There is no fake queue
// implementation standing in for it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-surface-platform/internal/config"
	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/health"
	"ai-surface-platform/internal/logging"
	"ai-surface-platform/internal/redis"
	"ai-surface-platform/internal/version"
)

// healthCheckInterval controls how often the worker re-verifies its
// dependencies while idle. The worker has no HTTP surface in Phase 1, so
// this is its "health mechanism": a periodic structured log line that
// operators/log-aggregation can alert on.
const healthCheckInterval = 30 * time.Second

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
	logger.Info("starting_worker",
		"version", info.Version,
		"commit", info.Commit,
		"environment", cfg.Application.Environment,
	)
	logger.Warn("worker_has_no_job_queue_yet",
		"note", "job processing is added in a later phase; this process currently only verifies infrastructure and demonstrates graceful shutdown",
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()
	logger.Info("database_verified")

	redisClient, err := redis.Connect(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("connecting to redis: %w", err)
	}
	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Warn("redis_close_error", "error", err)
		}
	}()
	logger.Info("redis_verified")

	dependencies := []health.Dependency{
		{Name: "database", Checker: db},
		{Name: "redis", Checker: redisClient},
	}

	logger.Info("worker_ready")

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			report := health.CheckAll(ctx, logger, dependencies)
			logger.Info("worker_health_check", "status", report.Status)
		case <-ctx.Done():
			logger.Info("worker_shutdown_signal_received")
			logger.Info("worker_stopped_cleanly")
			return nil
		}
	}
}
