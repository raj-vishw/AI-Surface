package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/health"
	"ai-surface-platform/internal/logging"
	"ai-surface-platform/internal/redis"
)

// NewHealthCommand returns the `ai-surface health` subcommand. It connects to
// every required dependency (PostgreSQL, Redis) using the effective
// configuration and reports whether each is reachable — the same check the
// server's /ready endpoint performs, but usable standalone without running
// the server. Exits non-zero if any dependency is unreachable.
func NewHealthCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check connectivity to required infrastructure (PostgreSQL, Redis)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}

			logger := logging.New(logging.Options{
				Level:  cfg.Logging.Level,
				Format: logging.Format(cfg.Logging.Format),
			})

			ctx := context.Background()

			var dependencies []health.Dependency

			db, dbErr := database.Connect(ctx, cfg.Database)
			if dbErr == nil {
				defer db.Close()
				dependencies = append(dependencies, health.Dependency{Name: "database", Checker: db})
			} else {
				dependencies = append(dependencies, health.Dependency{Name: "database", Checker: alwaysFails{dbErr}})
			}

			redisClient, redisErr := redis.Connect(ctx, cfg.Redis)
			if redisErr == nil {
				defer func() { _ = redisClient.Close() }()
				dependencies = append(dependencies, health.Dependency{Name: "redis", Checker: redisClient})
			} else {
				dependencies = append(dependencies, health.Dependency{Name: "redis", Checker: alwaysFails{redisErr}})
			}

			report := health.CheckAll(ctx, logger, dependencies)

			for _, c := range report.Checks {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s\n", c.Name, c.Status); err != nil {
					return err
				}
			}

			if report.Status != health.StatusOK {
				return fmt.Errorf("one or more dependencies are unreachable")
			}
			return nil
		},
	}
}

// alwaysFails is a health.Checker that reports the connection error a
// dependency failed with, so it still shows up in the report even though a
// live Checker (Pool/Client) could never be constructed.
type alwaysFails struct {
	err error
}

func (a alwaysFails) HealthCheck(context.Context) error {
	return a.err
}
