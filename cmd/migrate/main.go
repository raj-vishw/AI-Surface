// Command migrate applies and reports on database schema migrations.
//
// Usage:
//
//	migrate up       apply all pending migrations
//	migrate status   print the status of every known migration
//	migrate version  print the current (highest applied) migration version
package main

import (
	"context"
	"fmt"
	"os"

	"ai-surface-platform/internal/config"
	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/logging"
	"ai-surface-platform/internal/migrate"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || (args[0] != "up" && args[0] != "status" && args[0] != "version") {
		return fmt.Errorf("usage: migrate <up|status|version>")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	logger := logging.New(logging.Options{
		Level:  cfg.Logging.Level,
		Format: logging.Format(cfg.Logging.Format),
	})

	ctx := context.Background()
	dbPool, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer dbPool.Close()

	switch args[0] {
	case "up":
		applied, err := migrate.Up(ctx, dbPool.Pool)
		if err != nil {
			return fmt.Errorf("applying migrations: %w", err)
		}
		if len(applied) == 0 {
			logger.Info("no_migrations_to_apply")
			return nil
		}
		logger.Info("migrations_applied", "versions", applied)
		return nil

	case "status":
		statuses, err := migrate.StatusReport(ctx, dbPool.Pool)
		if err != nil {
			return fmt.Errorf("fetching migration status: %w", err)
		}
		for _, s := range statuses {
			state := "pending"
			if s.Applied {
				state = "applied"
			}
			fmt.Printf("%06d  %-40s  %s\n", s.Version, s.Description, state)
		}
		return nil

	case "version":
		current, found, err := migrate.CurrentVersion(ctx, dbPool.Pool)
		if err != nil {
			return fmt.Errorf("fetching current migration version: %w", err)
		}
		if !found {
			fmt.Println("no migrations applied")
			return nil
		}
		fmt.Printf("%06d\n", current)
		return nil
	}

	return nil // unreachable: args[0] validated above
}
