package main

import (
	"github.com/spf13/cobra"

	"ai-recon-platform/cmd/cli/commands"
)

// newRootCommand builds the `ai-recon` command tree.
//
// Phase 1 ships lifecycle/introspection commands only (version, config
// validate, health). Commands that perform discovery, fingerprinting, or
// probing (scan, fingerprint, report, monitor) belong to later phases and
// must not be added here yet.
func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ai-recon",
		Short: "ai-recon is the command-line interface for the AI Reconnaissance Platform",
		Long: "ai-recon is the command-line interface for the AI Reconnaissance Platform.\n" +
			"It is usable independently of the web dashboard and API server.",
		SilenceUsage: true,
	}

	root.PersistentFlags().String("config-dir", "", "override the configuration directory (defaults to $AI_RECON_CONFIG_DIR or \"configs\")")
	root.PersistentFlags().String("env", "", "override the environment (defaults to $AI_RECON_APP_ENV or \"development\")")
	root.PersistentFlags().String("log-level", "", "override the log level (debug, info, warn, error)")

	root.AddCommand(commands.NewVersionCommand())
	root.AddCommand(commands.NewConfigCommand())
	root.AddCommand(commands.NewHealthCommand())

	return root
}
