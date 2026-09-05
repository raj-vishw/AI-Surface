package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/httpclient"
	"ai-recon-platform/internal/intelligence"
	"ai-recon-platform/internal/intelligence/providers"
	"ai-recon-platform/internal/intelligence/risk"
	"ai-recon-platform/internal/logging"
	"ai-recon-platform/internal/repository/pagination"
	rulerepo "ai-recon-platform/internal/repository/rule"
	assetsvc "ai-recon-platform/internal/service/asset"
	intelligencesvc "ai-recon-platform/internal/service/intelligence"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewIntelCommand returns the `ai-recon intel` command group — Phase
// 10's threat intelligence entry point. It enriches already-known
// indicators with local platform context and (only when explicitly
// opted in) external provider data; it never blocks, remediates, or
// attributes an indicator to a specific threat actor (phase10.md §99/
// §100/§101).
func NewIntelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Look up and enrich threat intelligence for known indicators",
	}
	cmd.AddCommand(newIntelLookupCommand())
	cmd.AddCommand(newIntelEnrichCommand())
	cmd.AddCommand(newIntelEnrichProjectCommand())
	cmd.AddCommand(newIntelRefreshCommand())
	cmd.AddCommand(newIntelProvidersCommand())
	cmd.AddCommand(newIntelStatusCommand())
	return cmd
}

// buildIntelligenceService wires a *intelligencesvc.Service against a
// fresh database connection, registering every built-in provider
// (local/dns/certificate/technology always; threat_feed only when
// configured). Callers must close the returned *database.Pool.
func buildIntelligenceService(cmd *cobra.Command) (*intelligencesvc.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if !cfg.Intelligence.Enabled {
		return nil, nil, fmt.Errorf("intelligence.enabled is false in the effective configuration")
	}

	logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
	ctx := cmd.Context()
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	datasetSource := providers.NewDatasetSource()
	registry := intelligence.NewRegistry()
	if err := registry.Register(providers.NewLocalProvider(datasetSource)); err != nil {
		db.Close()
		return nil, nil, err
	}
	if err := registry.Register(providers.NewDNSProvider(datasetSource)); err != nil {
		db.Close()
		return nil, nil, err
	}
	if err := registry.Register(providers.NewCertificateProvider(datasetSource)); err != nil {
		db.Close()
		return nil, nil, err
	}
	if err := registry.Register(providers.NewTechnologyProvider(datasetSource)); err != nil {
		db.Close()
		return nil, nil, err
	}
	if cfg.Intelligence.ThreatFeed.BaseURL != "" {
		client := httpclient.NewFromConfig(cfg.HTTPClient)
		feedCfg := providers.ThreatFeedConfig{
			BaseURL: cfg.Intelligence.ThreatFeed.BaseURL, APIKeyEnv: cfg.Intelligence.ThreatFeed.APIKeyEnv,
			RequestsPerSecond: cfg.Intelligence.ThreatFeed.RequestsPerSecond, MaxRetries: cfg.Intelligence.ThreatFeed.MaxRetries,
		}
		if err := registry.Register(providers.NewThreatFeedProvider(client, feedCfg)); err != nil {
			db.Close()
			return nil, nil, err
		}
	}
	for id, enabled := range cfg.Intelligence.Providers {
		registry.SetEnabled(id, enabled)
	}

	engineCfg := intelligence.Config{
		Providers: cfg.Intelligence.Providers, ProviderTimeout: cfg.Intelligence.ProviderTimeout,
		ReputationTTL: cfg.Intelligence.ReputationTTL, VulnerabilityTTL: cfg.Intelligence.VulnerabilityTTL,
		ExternalEnrichmentEnabled: cfg.Intelligence.External.Enabled,
	}
	weights := toRiskWeights(cfg.Intelligence.Risk.Weights)

	targets := targetsvc.NewService(db)
	assets := assetsvc.NewService(db)
	svc := intelligencesvc.NewService(db, targets, assets, registry, datasetSource, engineCfg, weights, logger)
	// Phase 11 extension (phase11.md §98) — optional, additive: risk
	// calculations also consider open detection-rule matches when
	// Phase 11's tables exist. Never a second risk calculator — see
	// internal/intelligence/risk.Weights.DetectionMatchOpen.
	svc.WithDetectionMatches(rulerepo.NewPostgresRepository(db))
	return svc, db, nil
}

// toRiskWeights converts config.IntelligenceRiskWeightsConfig into
// risk.Weights — the mapping lives here (in the CLI wiring layer), the
// same place internal/config's own doc comments document
// InvestigationCorrelationConfig -> investigation.Config being mapped
// (cmd/cli/commands/investigate.go), since config.go never imports an
// engine package.
func toRiskWeights(w config.IntelligenceRiskWeightsConfig) risk.Weights {
	return risk.Weights{
		FindingSeverityCritical: w.FindingSeverityCritical, FindingSeverityHigh: w.FindingSeverityHigh,
		FindingSeverityMedium: w.FindingSeverityMedium, FindingSeverityLow: w.FindingSeverityLow,
		FindingSeverityInformational: w.FindingSeverityInformational, FindingConfidenceHigh: w.FindingConfidenceHigh,
		ExposureInternetFacing: w.ExposureInternetFacing, ExposureOpenServicePerUnit: w.ExposureOpenServicePerUnit,
		ExposureOpenServiceMax: w.ExposureOpenServiceMax, ExposureSensitiveEndpoint: w.ExposureSensitiveEndpoint,
		ExposureExposedAPI: w.ExposureExposedAPI, VulnerabilityConfirmed: w.VulnerabilityConfirmed,
		VulnerabilityProbable: w.VulnerabilityProbable, IntelligenceMalicious: w.IntelligenceMalicious,
		IntelligenceSuspicious: w.IntelligenceSuspicious, AssetCriticalityCritical: w.AssetCriticalityCritical,
		AssetCriticalityHigh: w.AssetCriticalityHigh, AssetCriticalityNormal: w.AssetCriticalityNormal,
		AssetCriticalityLow: w.AssetCriticalityLow, RecentChange: w.RecentChange,
	}
}

// inferIndicator classifies a bare string into an intelligence.Indicator
// — a URL if it parses with a host, an IP if net.ParseIP succeeds,
// otherwise a domain. --type overrides this when the caller knows better
// (e.g. "subdomain" vs "domain", or "hostname").
func inferIndicator(value, explicitType string) intelligence.Indicator {
	if explicitType != "" {
		return intelligence.Indicator{Type: intelligence.IndicatorType(explicitType), Value: value}
	}
	if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.Host != "" {
		return intelligence.Indicator{Type: intelligence.IndicatorURL, Value: value}
	}
	if ip := net.ParseIP(value); ip != nil {
		if strings.Contains(value, ":") {
			return intelligence.Indicator{Type: intelligence.IndicatorIPv6, Value: value}
		}
		return intelligence.Indicator{Type: intelligence.IndicatorIPv4, Value: value}
	}
	return intelligence.Indicator{Type: intelligence.IndicatorDomain, Value: value}
}

func resolveIntelTargetType(raw string) domaintarget.Type {
	t := domaintarget.Type(strings.ToUpper(raw))
	if t == "" {
		return domaintarget.TypeDomain
	}
	return t
}

func intelIndicatorFlags(cmd *cobra.Command) (targetValue, targetType, indicatorType *string) {
	targetValue = cmd.Flags().String("target", "", "the target this indicator belongs to (required)")
	targetType = cmd.Flags().String("target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	indicatorType = cmd.Flags().String("type", "", "domain|subdomain|ipv4|ipv6|url|hostname|certificate|technology|hash — inferred if omitted")
	return
}

func printLookupReport(cmd *cobra.Command, report intelligencesvc.LookupReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Indicator:\t%s (%s)\n", report.Indicator.Value, report.Indicator.Type)                 //nolint:errcheck
	fmt.Fprintln(w, "")                                                                                    //nolint:errcheck
	fmt.Fprintf(w, "Aggregated Verdict:\t%s\n", displayOrUnknown(string(report.Aggregated.Verdict)))       //nolint:errcheck
	fmt.Fprintf(w, "Aggregated Confidence:\t%s\n", displayOrUnknown(string(report.Aggregated.Confidence))) //nolint:errcheck
	fmt.Fprintf(w, "Supporting Sources:\t%d\n", report.Aggregated.SupportingSources)                       //nolint:errcheck
	fmt.Fprintf(w, "Conflicting Sources:\t%d\n", report.Aggregated.ConflictingSources)                     //nolint:errcheck
	fmt.Fprintf(w, "Explanation:\t%s\n", report.Aggregated.Explanation)                                    //nolint:errcheck
	fmt.Fprintln(w, "")                                                                                    //nolint:errcheck
	fmt.Fprintf(w, "Sources:\t%d record(s)\n", len(report.Records))                                        //nolint:errcheck
	for _, r := range report.Records {
		fmt.Fprintf(w, "  %s:\tverdict=%s confidence=%s retrieved=%s\n", r.ProviderID, r.Verdict, r.Confidence, r.RetrievedAt.Format("2006-01-02T15:04:05Z")) //nolint:errcheck
	}
	if len(report.CacheHits) > 0 {
		fmt.Fprintf(w, "Cache Hits:\t%s\n", strings.Join(report.CacheHits, ", ")) //nolint:errcheck
	}
	for _, e := range report.ProviderErrors {
		fmt.Fprintf(w, "Provider Error:\t%s: %v\n", e.ProviderID, e.Err) //nolint:errcheck
	}
	return w.Flush()
}

func displayOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func newIntelLookupCommand() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "lookup <indicator>",
		Short: "Show already-persisted intelligence for an indicator (no provider is queried)",
		Args:  cobra.ExactArgs(1),
	}
	targetValue, targetType, indicatorType := intelIndicatorFlags(cmd)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *targetValue == "" {
			return fmt.Errorf("--target is required")
		}
		svc, db, err := buildIntelligenceService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()

		target, err := svc.ResolveTarget(cmd.Context(), resolveIntelTargetType(*targetType), *targetValue)
		if err != nil {
			return err
		}
		indicator := inferIndicator(args[0], *indicatorType)
		report, err := svc.Show(cmd.Context(), target.ID, indicator)
		if err != nil {
			return err
		}
		return printLookupReport(cmd, report, jsonOut)
	}
	return cmd
}

func newIntelEnrichCommand() *cobra.Command {
	var jsonOut, dryRun bool
	cmd := &cobra.Command{
		Use:   "enrich <indicator>",
		Short: "Actively query every enabled, policy-permitted provider for an indicator",
		Args:  cobra.ExactArgs(1),
	}
	targetValue, targetType, indicatorType := intelIndicatorFlags(cmd)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report which providers would run without making any request")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *targetValue == "" {
			return fmt.Errorf("--target is required")
		}
		svc, db, err := buildIntelligenceService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()

		target, err := svc.ResolveTarget(cmd.Context(), resolveIntelTargetType(*targetType), *targetValue)
		if err != nil {
			return err
		}
		indicator := inferIndicator(args[0], *indicatorType)

		if dryRun {
			plan := svc.Plan()
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Providers that would run:\t%s\n", strings.Join(plan, ", ")) //nolint:errcheck
			fmt.Fprintln(w, "External requests:\t0")                                    //nolint:errcheck
			fmt.Fprintln(w, "Records to update:\t0 (dry run)")                          //nolint:errcheck
			return w.Flush()
		}

		report, err := svc.Enrich(cmd.Context(), target.ID, indicator)
		if err != nil {
			return err
		}
		return printLookupReport(cmd, report, jsonOut)
	}
	return cmd
}

func newIntelRefreshCommand() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "refresh <indicator>",
		Short: "Invalidate cached provider results for an indicator and re-enrich it",
		Args:  cobra.ExactArgs(1),
	}
	targetValue, targetType, indicatorType := intelIndicatorFlags(cmd)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *targetValue == "" {
			return fmt.Errorf("--target is required")
		}
		svc, db, err := buildIntelligenceService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()

		target, err := svc.ResolveTarget(cmd.Context(), resolveIntelTargetType(*targetType), *targetValue)
		if err != nil {
			return err
		}
		report, err := svc.Refresh(cmd.Context(), target.ID, inferIndicator(args[0], *indicatorType))
		if err != nil {
			return err
		}
		return printLookupReport(cmd, report, jsonOut)
	}
	return cmd
}

func newIntelProvidersCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List every registered intelligence provider and its health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tVERSION\tENABLED\tHEALTH\tSUCCESS\tERRORS") //nolint:errcheck
			for _, p := range svc.ProvidersStatus() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\t%d\t%d\n", p.ID, p.Name, p.Version, p.Enabled, p.Health.Status, p.Health.SuccessCount, p.Health.ErrorCount) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newIntelStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the intelligence engine's effective configuration and provider status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Enabled:\t%t\n", cfg.Intelligence.Enabled)                                 //nolint:errcheck
			fmt.Fprintf(w, "External Enrichment:\t%t\n", cfg.Intelligence.External.Enabled)            //nolint:errcheck
			fmt.Fprintf(w, "Threat Feed Configured:\t%t\n", cfg.Intelligence.ThreatFeed.BaseURL != "") //nolint:errcheck
			fmt.Fprintln(w, "")                                                                        //nolint:errcheck
			fmt.Fprintln(w, "ID\tENABLED\tHEALTH\tLAST SUCCESS")                                       //nolint:errcheck
			for _, p := range svc.ProvidersStatus() {
				last := "never"
				if !p.Health.LastSuccess.IsZero() {
					last = p.Health.LastSuccess.Format("2006-01-02T15:04:05Z")
				}
				fmt.Fprintf(w, "%s\t%t\t%s\t%s\n", p.ID, p.Enabled, p.Health.Status, last) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newIntelEnrichProjectCommand() *cobra.Command {
	var targetType string
	var limit int
	cmd := &cobra.Command{
		Use:   "enrich-project <target>",
		Short: "Enrich every known asset within a target, up to --limit assets (bounded batch enrichment)",
		Args:  cobra.ExactArgs(1),
	}
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of assets to enrich in this run (phase10.md §71 — batch enrichment must be bounded)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		svc, db, err := buildIntelligenceService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()

		target, err := svc.ResolveTarget(cmd.Context(), resolveIntelTargetType(targetType), args[0])
		if err != nil {
			return err
		}

		assetPage, err := svc.ListTargetAssets(cmd.Context(), target.ID, pagination.Params{Limit: limit})
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ASSET_ID\tRISK SCORE\tSEVERITY\tVULNERABILITY MATCHES") //nolint:errcheck
		for _, a := range assetPage.Items {
			enrichment, err := svc.EnrichAsset(cmd.Context(), a.ID)
			if err != nil {
				fmt.Fprintf(w, "%s\tERROR\t%v\t-\n", a.ID, err) //nolint:errcheck
				continue
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%d\n", a.ID, enrichment.Risk.Score, enrichment.Risk.Severity, len(enrichment.VulnerabilityMatches)) //nolint:errcheck
		}
		return w.Flush()
	}
	return cmd
}
