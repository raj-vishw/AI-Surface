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
// (TCP connect discovery); Phase 5 added `dns-scan`/`subdomain-scan` (DNS
// record and subdomain discovery); Phase 6 added `fingerprint` (passive
// technology identification against already-collected evidence — no
// network/DNS request of its own); Phase 7 adds `endpoint-scan` (bounded
// endpoint & API discovery/crawling — GET requests only, never a
// vulnerability scanner); Phase 8 adds `findings` (evidence-driven
// finding/vulnerability detection — passive by default, never an exploit
// or credential-attack tool); Phase 9 adds `investigate` (analyst case
// management and finding correlation — an analytical aid, never an
// offensive or automatic-remediation tool); Phase 10 adds `intel` and
// `risk` (threat intelligence enrichment and risk scoring over
// already-known indicators/entities — local platform data by default,
// external providers only when explicitly opted in; never a blocking,
// remediation, or attribution tool); Phase 11 adds `detection` and
// `alert` (a deterministic, versioned, testable detection rule engine
// evaluating this platform's own normalized findings/asset/endpoint/
// fingerprint/intelligence observations — never raw external logs; no
// autonomous response, no offensive automation). Phase 12 adds
// `correlation` and `chain` (a deterministic, explainable correlation
// engine linking findings/detection matches/alerts/intelligence/assets
// into graphs and, where the evidence classifies into one, an attack
// chain — never automatically labeled a confirmed attack; analyst
// confirmation/dismissal only). Commands belonging to later phases
// (report, monitor) must not be added here yet.
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
	root.AddCommand(commands.NewFingerprintCommand())
	root.AddCommand(commands.NewEndpointScanCommand())
	root.AddCommand(commands.NewFindingsCommand())
	root.AddCommand(commands.NewInvestigateCommand())
	root.AddCommand(commands.NewIntelCommand())
	root.AddCommand(commands.NewRiskCommand())
	root.AddCommand(commands.NewDetectionCommand())
	root.AddCommand(commands.NewAlertCommand())
	root.AddCommand(commands.NewCorrelationCommand())
	root.AddCommand(commands.NewChainCommand())

	return root
}
