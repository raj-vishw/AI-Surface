package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"ai-surface-platform/internal/config"
	"ai-surface-platform/internal/database"
	discoveryendpoint "ai-surface-platform/internal/discovery/endpoint"
	discoverysvc "ai-surface-platform/internal/discovery/service"
	domaintarget "ai-surface-platform/internal/domain/target"
	"ai-surface-platform/internal/logging"
	assetsvc "ai-surface-platform/internal/service/asset"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewEndpointScanCommand returns the `ai-surface endpoint-scan` command —
// Phase 7's endpoint & API discovery entry point: bounded crawling, HTML/
// JavaScript static extraction, robots.txt/sitemap.xml, and OpenAPI/
// Swagger parsing against an already-authorized target. It is an
// inventory engine, never a vulnerability scanner (phase7.md §3/§90) —
// it never sends anything but GET requests, and never submits a form.
func NewEndpointScanCommand() *cobra.Command {
	var (
		targetType   string
		seedsCSV     string
		depth        int
		maxPages     int
		maxEndpoints int
		timeout      string
		concurrency  int
		rate         float64
		format       string
		profile      string
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:   "endpoint-scan --target <target>",
		Short: "Discover application endpoints and API surface from an authorized target",
		Long: "Runs the endpoint discovery engine: bounded crawling from the target's known\n" +
			"HTTP(S) assets (or explicit --seed URLs), HTML link/form extraction, JavaScript static\n" +
			"route extraction, robots.txt/sitemap.xml parsing, and OpenAPI/Swagger discovery. It only\n" +
			"ever sends GET requests — it never submits a form and never sends PUT/PATCH/DELETE merely\n" +
			"to discover whether they work. It refuses to run against a target that is not AUTHORIZED,\n" +
			"and it never sends a request in dry-run mode (security.dry_run, or --dry-run).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("--target is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Discovery.Endpoint.Enabled {
				return fmt.Errorf("discovery.endpoint.enabled is false in the effective configuration")
			}

			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("timeout") {
				d, err := time.ParseDuration(timeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
				cfg.Discovery.Endpoint.Timeout = d
			}
			if cmd.Flags().Changed("concurrency") {
				cfg.Discovery.Endpoint.MaxConcurrency = concurrency
			}
			if cmd.Flags().Changed("requests-per-second") {
				cfg.Discovery.Endpoint.RequestsPerSecond = rate
			}
			if cmd.Flags().Changed("depth") {
				cfg.Discovery.Endpoint.MaxDepth = depth
			}
			if cmd.Flags().Changed("max-pages") {
				cfg.Discovery.Endpoint.MaxPages = maxPages
			}
			if cmd.Flags().Changed("max-endpoints") {
				cfg.Discovery.Endpoint.MaxEndpoints = maxEndpoints
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration after flag overrides: %w", err)
			}

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = domaintarget.TypeDomain
			}

			var seeds []string
			if seedsCSV != "" {
				for _, s := range strings.Split(seedsCSV, ",") {
					if s = strings.TrimSpace(s); s != "" {
						seeds = append(seeds, s)
					}
				}
			}

			// Operational logs go to stderr unconditionally, so --format
			// json's stdout is always valid, log-free JSON (phase7.md §62).
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

			summary, dryRunReport, changes, err := discovery.RunEndpoint(ctx, discoverysvc.EndpointRequest{
				TargetType: resolvedType, TargetValue: target, Profile: profile, SeedURLs: seeds,
				DryRun: cfg.Security.DryRun, Config: discoveryendpoint.FromAppConfig(cfg.Discovery.Endpoint),
			})
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				return printEndpointDryRun(cmd, dryRunReport)
			}
			if format == "json" {
				return printEndpointJSON(cmd, target, summary, changes)
			}
			return printEndpointTable(cmd, target, summary, changes)
		},
	}

	cmd.Flags().String("target", "", "the target to scan (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&seedsCSV, "seed", "", "comma-separated explicit seed URLs — overrides the target's own known HTTP(S) assets")
	cmd.Flags().IntVar(&depth, "depth", 0, "override discovery.endpoint.max_depth")
	cmd.Flags().IntVar(&maxPages, "max-pages", 0, "override discovery.endpoint.max_pages")
	cmd.Flags().IntVar(&maxEndpoints, "max-endpoints", 0, "override discovery.endpoint.max_endpoints")
	cmd.Flags().StringVar(&timeout, "timeout", "", "override discovery.endpoint.timeout (e.g. 10s)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "override discovery.endpoint.max_concurrency")
	cmd.Flags().Float64Var(&rate, "requests-per-second", 0, "override discovery.endpoint.requests_per_second (0 = unlimited)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().StringVar(&profile, "profile", "", "named profile from configuration (quick, standard, comprehensive)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — report the crawl plan without making any request")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func printEndpointDryRun(cmd *cobra.Command, report *discoverysvc.EndpointDryRunReport) error {
	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "Endpoint Discovery Plan\n\nTarget:\n    %s\n\nSeeds:\n", report.Target); err != nil {
		return err
	}
	for _, s := range report.Seeds {
		if _, err := fmt.Fprintf(out, "    %s\n", s); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "\nMax depth:\n    %d\n\nMax pages:\n    %d\n\nMax endpoints:\n    %d\n\nSources:\n    %s\n",
		report.MaxDepth, report.MaxPages, report.MaxEndpoints, strings.Join(report.Sources, "\n    "))
	return err
}

// printEndpointTable reuses errWriter (defined in fingerprint.go — both
// files are the same "commands" package, so this small write-error-
// accumulating helper is shared rather than duplicated).
func printEndpointTable(cmd *cobra.Command, target string, summary *discoveryendpoint.Summary, changes []discoverysvc.EndpointChange) error {
	ew := &errWriter{w: cmd.OutOrStdout()}
	ew.printf("ENDPOINTS\n\n")

	w := tabwriter.NewWriter(ew.w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "METHOD\tPATH\tTYPE\tSTATUS\tSOURCE") //nolint:errcheck // tabwriter buffers; the real write happens (and is checked) at Flush
	for _, r := range summary.Results {
		status := "-"
		if r.StatusCode != nil {
			status = fmt.Sprintf("%d", *r.StatusCode)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Method, r.Path, r.Classification, status, strings.Join(r.Sources, ",")) //nolint:errcheck // see above
	}
	if err := w.Flush(); err != nil {
		return err
	}

	ew.printf("\nEndpoint Discovery Summary\n")
	ew.printf("Target:                  %s\n", target)
	ew.printf("Pages fetched:           %d\n", summary.PagesFetched)
	ew.printf("Endpoints discovered:    %d\n", summary.EndpointsDiscovered)
	ew.printf("Duplicates skipped:      %d\n", summary.Duplicates)
	ew.printf("Scope rejections:        %d\n", summary.ScopeRejections)
	ew.printf("Redirects:               %d\n", summary.Redirects)
	ew.printf("Truncated responses:     %d\n", summary.Truncated)
	ew.printf("Errors:                  %d\n", summary.Errors)
	ew.printf("Duration:                %s\n", summary.Duration)

	if len(changes) > 0 {
		ew.printf("\nChanges since previous scan:\n")
		for _, c := range changes {
			ew.printf("  %s: %s %s\n", c.Type, c.Method, c.URL)
		}
	}
	return ew.err
}

type jsonEndpoint struct {
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Classification string   `json:"classification"`
	APIType        string   `json:"api_type,omitempty"`
	APIVersion     string   `json:"api_version,omitempty"`
	StatusCode     *int     `json:"status_code,omitempty"`
	Sources        []string `json:"sources"`
	Confidence     float64  `json:"confidence"`
	Documented     bool     `json:"documented"`
	Observed       bool     `json:"observed"`
	Inferred       bool     `json:"inferred"`
}

type jsonEndpointScanResult struct {
	ScanID    string         `json:"scan_id"`
	Asset     string         `json:"asset"`
	Endpoints []jsonEndpoint `json:"endpoints"`
}

func printEndpointJSON(cmd *cobra.Command, target string, summary *discoveryendpoint.Summary, _ []discoverysvc.EndpointChange) error {
	endpoints := make([]jsonEndpoint, len(summary.Results))
	for i, r := range summary.Results {
		endpoints[i] = jsonEndpoint{
			Method: r.Method, Path: r.Path, Classification: string(r.Classification),
			APIType: r.APIType, APIVersion: r.APIVersion, StatusCode: r.StatusCode,
			Sources: r.Sources, Confidence: r.Confidence,
			Documented: r.Documented, Observed: r.Observed, Inferred: r.Inferred,
		}
	}
	result := jsonEndpointScanResult{ScanID: summary.ScanID.String(), Asset: target, Endpoints: endpoints}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
