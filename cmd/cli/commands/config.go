// Package commands implements the ai-recon CLI's subcommands.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"ai-recon-platform/internal/config"
)

// loadConfig loads the effective configuration, applying the CLI's
// persistent --config-dir/--env/--log-level flags on top of the normal
// defaults -> config files -> environment variables precedence chain (see
// internal/config.Load). It is the single place every subcommand goes
// through so behavior stays consistent.
func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	if v, _ := cmd.Flags().GetString("config-dir"); v != "" {
		if err := os.Setenv(config.EnvVarConfigDir, v); err != nil {
			return nil, fmt.Errorf("setting %s: %w", config.EnvVarConfigDir, err)
		}
	}
	if v, _ := cmd.Flags().GetString("env"); v != "" {
		if err := os.Setenv(config.EnvVarEnvironment, v); err != nil {
			return nil, fmt.Errorf("setting %s: %w", config.EnvVarEnvironment, err)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	if v, _ := cmd.Flags().GetString("log-level"); v != "" {
		config.ApplyOverrides(cfg, config.Overrides{LoggingLevel: &v})
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid configuration after --log-level override: %w", err)
		}
	}

	return cfg, nil
}

// NewConfigCommand returns the `ai-recon config` parent command.
func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate configuration",
	}
	cmd.AddCommand(newConfigValidateCommand())
	return cmd
}

// newConfigValidateCommand returns the `ai-recon config validate`
// subcommand, which loads and validates the effective configuration
// without starting any server or performing any scan/probe activity.
func newConfigValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Load and validate the effective configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"configuration is valid\n  environment: %s\n  database:    %s\n  redis:       %s\n  log level:   %s\n",
				cfg.Application.Environment, cfg.Database.RedactedDSN(), cfg.Redis.Address, cfg.Logging.Level,
			)
			return err
		},
	}
}
