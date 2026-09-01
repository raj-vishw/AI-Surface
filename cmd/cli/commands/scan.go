package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	discoveryhttp "ai-recon-platform/internal/discovery/http"
	"ai-recon-platform/internal/discovery/model"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/logging"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewScanCommand returns the `ai-recon scan` command — Phase 3's HTTP
// discovery entry point. It requires the target to already exist and be
// authorized (`ai-recon target create` + `ai-recon target authorize`,
// below); scan itself never creates or authorizes a target.
func NewScanCommand() *cobra.Command {
	var (
		targetType  string
		profile     string
		format      string
		timeout     string
		concurrency int
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "scan --target <target>",
		Short: "Run HTTP discovery against an authorized target",
		Long: "scan runs the Phase 3 HTTP discovery engine against an already-created, already-\n" +
			"authorized target: it generates candidate URLs, requests each within scope, classifies\n" +
			"the response, and persists discovered assets/endpoints/evidence through the Phase 2\n" +
			"persistence layer. It refuses to run against a target that is not AUTHORIZED, and it\n" +
			"never sends a request in dry-run mode (security.dry_run, or --dry-run).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("--target is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Discovery.HTTP.Enabled {
				return fmt.Errorf("discovery.http.enabled is false in the effective configuration")
			}

			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("timeout") {
				d, err := time.ParseDuration(timeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
				cfg.Discovery.HTTP.Timeout = d
			}
			if cmd.Flags().Changed("concurrency") {
				cfg.Discovery.HTTP.MaxConcurrency = concurrency
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration after flag overrides: %w", err)
			}

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = inferTargetType(target)
			}

			// Operational logs go to stderr unconditionally, so --format
			// json's stdout is always valid, log-free JSON (phase3.md
			// §32).
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

			summary, dryRunReport, err := discovery.Run(ctx, discoverysvc.Request{
				TargetType:  resolvedType,
				TargetValue: target,
				Profile:     profile,
				DryRun:      cfg.Security.DryRun,
				Config:      discoveryhttp.FromAppConfig(cfg.Discovery.HTTP),
			})
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				return printDryRun(cmd, dryRunReport)
			}
			return printSummary(cmd, summary, format)
		},
	}

	cmd.Flags().String("target", "", "the target to scan — a URL (http://host:port), or a HOST/DOMAIN value (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — auto-detected from --target if omitted (a value containing \"://\" is treated as URL, otherwise DOMAIN)")
	cmd.Flags().StringVar(&profile, "profile", "", "named path profile from configuration (e.g. quick, comprehensive) — omit to use the full configured path set")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().StringVar(&timeout, "timeout", "", "override discovery.http.timeout (e.g. 5s)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "override discovery.http.max_concurrency")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — report candidate URLs without requesting them")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func inferTargetType(target string) domaintarget.Type {
	if strings.Contains(target, "://") {
		return domaintarget.TypeURL
	}
	return domaintarget.TypeDomain
}

func printDryRun(cmd *cobra.Command, report *discoverysvc.DryRunReport) error {
	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "DRY RUN\n\nTarget:\n%s\n\nWould request:\n", report.Target); err != nil {
		return err
	}
	for _, c := range report.Candidates {
		path := c.URL
		if u, err := url.Parse(c.URL); err == nil {
			path = u.Path
			if path == "" {
				path = "/"
			}
		}
		if _, err := fmt.Fprintf(out, "%s %s\n", c.Method, path); err != nil {
			return err
		}
	}
	return nil
}

func printSummary(cmd *cobra.Command, summary *model.Summary, format string) error {
	switch format {
	case "json":
		// JSON output is the machine-readable contract: nothing but valid
		// JSON goes to stdout in this branch (phase3.md §32) — operational
		// logs are already routed to stderr (see NewScanCommand).
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	case "table", "":
		return printTable(cmd, summary)
	default:
		return fmt.Errorf("unrecognized --format %q (want table or json)", format)
	}
}

// printTable renders the per-URL result table (phase3.md §32) followed by
// the aggregate scan summary (§27).
func printTable(cmd *cobra.Command, summary *model.Summary) error {
	out := cmd.OutOrStdout()

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "URL\tSTATUS\tTYPE\tAI"); err != nil {
		return err
	}
	for _, r := range summary.Results {
		var status string
		if r.Error != "" {
			status = "ERROR"
		} else if r.Skipped {
			status = "SKIPPED"
		} else {
			status = fmt.Sprintf("%d", r.StatusCode)
		}
		ai := "no"
		if r.AIEndpointCandidate {
			ai = "yes"
		}
		serviceType := r.ServiceType
		if serviceType == "" {
			serviceType = model.ServiceUnknown
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.URL, status, serviceType, ai); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "\nHTTP Discovery Summary\n\n"+
		"Target:              %s\n"+
		"URLs attempted:      %d\n"+
		"Successful:          %d\n"+
		"Failed:              %d\n"+
		"HTTP endpoints:      %d\n"+
		"API candidates:      %d\n"+
		"AI candidates:       %d\n"+
		"Redirects:           %d\n"+
		"Errors:              %d\n\n"+
		"Duration: %s\n",
		summary.Target, summary.URLsAttempted, summary.Successful, summary.Failed,
		summary.HTTPEndpoints, summary.APICandidates, summary.AICandidates,
		summary.Redirects, summary.Errors, summary.Duration,
	)
	return err
}
