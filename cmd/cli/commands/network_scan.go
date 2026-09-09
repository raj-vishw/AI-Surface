package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"ai-surface-platform/internal/config"
	"ai-surface-platform/internal/database"
	discoverynet "ai-surface-platform/internal/discovery/network"
	discoverysvc "ai-surface-platform/internal/discovery/service"
	domaintarget "ai-surface-platform/internal/domain/target"
	"ai-surface-platform/internal/logging"
	assetsvc "ai-surface-platform/internal/service/asset"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewNetworkScanCommand returns the `ai-surface network-scan` command —
// Phase 4's TCP connect discovery entry point. Like `scan` (Phase 3), it
// requires the target to already exist and be authorized; network-scan
// never creates or authorizes a target itself.
func NewNetworkScanCommand() *cobra.Command {
	var (
		targetType  string
		portsSpec   string
		profile     string
		format      string
		timeout     string
		concurrency int
		rate        float64
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "network-scan --target <target>",
		Short: "Run TCP connect discovery against an authorized target",
		Long: "network-scan runs the TCP connect discovery engine against an already-\n" +
			"created, already-authorized target: it expands the target (HOST/IP as-is, CIDR within\n" +
			"the configured host limit), attempts a bounded-concurrency TCP connection to every\n" +
			"host:port combination within scope, conservatively classifies open ports, and persists\n" +
			"them as PORT assets. It refuses to run against a target that is not AUTHORIZED, and it\n" +
			"never opens a TCP connection in dry-run mode (security.dry_run, or --dry-run).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("--target is required")
			}
			if portsSpec == "" && profile == "" {
				return fmt.Errorf("either --ports or --profile is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Discovery.Network.Enabled {
				return fmt.Errorf("discovery.network.enabled is false in the effective configuration")
			}

			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("timeout") {
				d, err := time.ParseDuration(timeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
				cfg.Discovery.Network.ConnectTimeout = d
			}
			if cmd.Flags().Changed("concurrency") {
				cfg.Discovery.Network.MaxConcurrency = concurrency
			}
			if cmd.Flags().Changed("rate") {
				cfg.Discovery.Network.RequestsPerSecond = rate
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration after flag overrides: %w", err)
			}

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = inferNetworkTargetType(target)
			}

			// Operational logs go to stderr unconditionally, so --format
			// json's stdout is always valid, log-free JSON (phase4.md §31).
			logger := logging.New(logging.Options{
				Level:  cfg.Logging.Level,
				Format: logging.Format(cfg.Logging.Format),
				Output: os.Stderr,
			})

			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			discovery := discoverysvc.NewService(targets, assets, logger)

			summary, dryRunReport, err := discovery.RunNetwork(ctx, discoverysvc.NetworkRequest{
				TargetType:  resolvedType,
				TargetValue: target,
				Profile:     profile,
				PortsSpec:   portsSpec,
				DryRun:      cfg.Security.DryRun,
				Config:      discoverynet.FromAppConfig(cfg.Discovery.Network),
			})
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				return printNetworkDryRun(cmd, dryRunReport)
			}
			return printNetworkSummary(cmd, summary, format)
		},
	}

	cmd.Flags().String("target", "", "the target to scan — a HOST, IP, or CIDR block (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "HOST|IP|CIDR — auto-detected from --target if omitted")
	cmd.Flags().StringVar(&portsSpec, "ports", "", "ports to scan: single (80), list (80,443), range (8000-8010), or mixed — required unless --profile is given")
	cmd.Flags().StringVar(&profile, "profile", "", "named port profile from configuration (e.g. quick, standard, comprehensive) — required unless --ports is given")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().StringVar(&timeout, "timeout", "", "override discovery.network.connect_timeout (e.g. 2s)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "override discovery.network.max_concurrency")
	cmd.Flags().Float64Var(&rate, "rate", 0, "override discovery.network.requests_per_second (0 = unlimited)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — report host:port pairs that would be scanned without connecting")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func inferNetworkTargetType(target string) domaintarget.Type {
	if strings.Contains(target, "/") {
		return domaintarget.TypeCIDR
	}
	if net.ParseIP(target) != nil {
		return domaintarget.TypeIP
	}
	return domaintarget.TypeHost
}

func printNetworkDryRun(cmd *cobra.Command, report *discoverysvc.NetworkDryRunReport) error {
	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "DRY RUN\n\nTarget:\n%s\n\nWould scan:\n", report.Target); err != nil {
		return err
	}
	for _, host := range report.Hosts {
		for _, port := range report.Ports {
			if _, err := fmt.Fprintf(out, "%s:%d\n", host, port); err != nil {
				return err
			}
		}
	}
	return nil
}

func printNetworkSummary(cmd *cobra.Command, summary *discoverynet.Summary, format string) error {
	switch format {
	case "json":
		// JSON output is the machine-readable contract: nothing but valid
		// JSON goes to stdout in this branch — operational logs are
		// already routed to stderr (see NewNetworkScanCommand).
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	case "table", "":
		return printNetworkTable(cmd, summary)
	default:
		return fmt.Errorf("unrecognized --format %q (want table or json)", format)
	}
}

// printNetworkTable renders the per-port result table (phase4.md §32)
// followed by the aggregate scan summary (§30). A candidate (HTTP or AI)
// is marked distinctly from a confirmed service classification — see the
// CANDIDATE column, which is never the same thing as SERVICE.
func printNetworkTable(cmd *cobra.Command, summary *discoverynet.Summary) error {
	out := cmd.OutOrStdout()

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "HOST\tPORT\tPROTOCOL\tSTATE\tSERVICE\tCANDIDATE"); err != nil {
		return err
	}
	for _, r := range summary.Results {
		state := string(r.State)
		if r.Skipped {
			state = "SKIPPED"
		}
		service := r.Service
		if service == "" {
			service = discoverynet.ServiceUnknown
		}
		candidate := "-"
		switch {
		case r.AIServiceCandidate:
			candidate = "AI_CANDIDATE"
		case r.HTTPCandidate:
			candidate = "HTTP_CANDIDATE"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", r.Host, r.Port, r.Protocol, state, service, candidate); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "\nNetwork Discovery Summary\n\n"+
		"Target:                %s\n"+
		"Hosts scanned:         %d\n"+
		"Ports attempted:       %d\n"+
		"Open ports:            %d\n"+
		"Closed ports:          %d\n"+
		"Timeouts:              %d\n"+
		"Errors:                %d\n\n"+
		"HTTP candidates:       %d\n"+
		"AI service candidates: %d\n\n"+
		"Duration: %s\n",
		summary.Target, summary.HostsScanned, summary.PortsAttempted, summary.Open, summary.Closed,
		summary.Timeouts, summary.Errors, summary.HTTPCandidates, summary.AICandidates, summary.Duration,
	)
	return err
}
