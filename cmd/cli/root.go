package main

import (
	"github.com/spf13/cobra"

	"ai-recon-platform/cmd/cli/commands"
)

// newRootCommand builds the `ai-recon` command tree.
//
// Phase 1 shipped lifecycle/introspection commands (version, config
// validate, health). Phase 2 added `target`/`asset` as development
// diagnostics for the persistence layer — see their Long help text.
// Phase 3 added `scan` (HTTP discovery); Phase 4 added `network-scan`
// (TCP connect discovery); Phase 5 adds `dns-scan`/`subdomain-scan` (DNS
// record and subdomain discovery). Commands belonging to later phases
// (fingerprint, report, monitor) must not be added here yet.
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
	root.AddCommand(commands.NewTargetCommand())
	root.AddCommand(commands.NewAssetCommand())
	root.AddCommand(commands.NewScanCommand())
	root.AddCommand(commands.NewNetworkScanCommand())
	root.AddCommand(commands.NewDNSScanCommand())
	root.AddCommand(commands.NewSubdomainScanCommand())

	return root
}
