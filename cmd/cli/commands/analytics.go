package commands

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-surface-platform/internal/analytics"
	"ai-surface-platform/internal/database"
	analyticsrepo "ai-surface-platform/internal/repository/analytics"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewAnalyticsCommand returns the `ai-surface analytics` command group —
// Phase 14's dashboard/analytics layer. Every subcommand is a read-only
// aggregate query over Phase 2-13's own data; nothing here writes
// anything (phase14.md's own "primarily a visualization/analytics/
// reporting/export/observability phase").
func NewAnalyticsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analytics",
		Short: "Security analytics and dashboard aggregates",
	}
	cmd.AddCommand(newAnalyticsOverviewCommand())
	cmd.AddCommand(newAnalyticsRiskCommand())
	cmd.AddCommand(newAnalyticsAlertsCommand())
	cmd.AddCommand(newAnalyticsDetectionsCommand())
	cmd.AddCommand(newAnalyticsFindingsCommand())
	cmd.AddCommand(newAnalyticsAssetsCommand())
	cmd.AddCommand(newAnalyticsAttackSurfaceCommand())
	cmd.AddCommand(newAnalyticsCorrelationsCommand())
	cmd.AddCommand(newAnalyticsAttackChainsCommand())
	cmd.AddCommand(newAnalyticsInvestigationsCommand())
	cmd.AddCommand(newAnalyticsIntelligenceCommand())
	cmd.AddCommand(newAnalyticsAICommand())
	cmd.AddCommand(newAnalyticsPostureCommand())
	cmd.AddCommand(newAnalyticsTimeSeriesCommand())
	return cmd
}

func buildAnalyticsService(cmd *cobra.Command) (*analytics.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	db, err := database.Connect(cmd.Context(), cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	repo := analyticsrepo.NewPostgresRepository(db)
	svc := analytics.NewService(repo, analytics.NewCache(analytics.DefaultCacheTTL))
	return svc, db, nil
}

// resolveAnalyticsTarget resolves --target/--target-type into a target
// id, mirroring every other phase's identical CLI convention.
func resolveAnalyticsTarget(cmd *cobra.Command, db *database.Pool, targetValue, targetType string) (uuid.UUID, error) {
	if targetValue == "" {
		return uuid.Nil, fmt.Errorf("--target is required")
	}
	targets := targetsvc.NewService(db)
	t, err := targets.GetByValue(cmd.Context(), resolveCorrelationTargetType(targetType), targetValue)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// rangeFlags is the flag set every range-aware analytics/report command
// shares (phase14.md §20/§72/§73).
type rangeFlags struct {
	preset, interval, from, to string
}

func addRangeFlags(cmd *cobra.Command) *rangeFlags {
	rf := &rangeFlags{}
	cmd.Flags().StringVar(&rf.preset, "range", "7d", "24h|7d|30d|90d")
	cmd.Flags().StringVar(&rf.interval, "interval", "", "override the auto-selected bucket interval: hour|day|week")
	cmd.Flags().StringVar(&rf.from, "from", "", "RFC3339 start (overrides --range)")
	cmd.Flags().StringVar(&rf.to, "to", "", "RFC3339 end (overrides --range)")
	return rf
}

func (rf *rangeFlags) resolve() (analytics.TimeRange, error) {
	if rf.from != "" || rf.to != "" {
		from, err := time.Parse(time.RFC3339, rf.from)
		if err != nil {
			return analytics.TimeRange{}, fmt.Errorf("invalid --from: %w", err)
		}
		to, err := time.Parse(time.RFC3339, rf.to)
		if err != nil {
			return analytics.TimeRange{}, fmt.Errorf("invalid --to: %w", err)
		}
		return analytics.ResolveRange("", from, to, rf.interval)
	}
	return analytics.ResolveRange(analytics.RangePreset(rf.preset), time.Time{}, time.Time{}, rf.interval)
}

func printNamedCounts(w *tabwriter.Writer, title string, counts []analyticsrepo.NamedCount) {
	fmt.Fprintf(w, "%s:\n", title) //nolint:errcheck
	if len(counts) == 0 {
		fmt.Fprintln(w, "  (none)") //nolint:errcheck
		return
	}
	for _, c := range counts {
		fmt.Fprintf(w, "  %s\t%d\n", c.Name, c.Count) //nolint:errcheck
	}
}

func printBuckets(w *tabwriter.Writer, title string, buckets []analyticsrepo.Bucket) {
	fmt.Fprintf(w, "%s:\n", title) //nolint:errcheck
	if len(buckets) == 0 {
		fmt.Fprintln(w, "  (no data in range)") //nolint:errcheck
		return
	}
	for _, b := range buckets {
		fmt.Fprintf(w, "  %s\t%d\n", b.BucketStart.Format(time.RFC3339), b.Count) //nolint:errcheck
	}
}

func newAnalyticsOverviewCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{
		Use:   "overview",
		Short: "Executive/SOC summary: headline counts across every subsystem",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildAnalyticsService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
			if err != nil {
				return err
			}
			o, err := svc.Overview(cmd.Context(), targetID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Total Assets:\t%d\n", o.TotalAssets)                   //nolint:errcheck
			fmt.Fprintf(w, "Monitored Assets:\t%d\n", o.MonitoredAssets)           //nolint:errcheck
			fmt.Fprintf(w, "Open Findings:\t%d\n", o.OpenFindings)                 //nolint:errcheck
			fmt.Fprintf(w, "Open Alerts:\t%d\n", o.OpenAlerts)                     //nolint:errcheck
			fmt.Fprintf(w, "Active Investigations:\t%d\n", o.ActiveInvestigations) //nolint:errcheck
			fmt.Fprintf(w, "Critical Risk Assets:\t%d\n", o.CriticalRiskAssets)    //nolint:errcheck
			fmt.Fprintf(w, "High Risk Assets:\t%d\n", o.HighRiskAssets)            //nolint:errcheck
			fmt.Fprintf(w, "Open Correlations:\t%d\n", o.OpenCorrelations)         //nolint:errcheck
			fmt.Fprintf(w, "Intelligence Records:\t%d\n", o.IntelligenceRecords)   //nolint:errcheck
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	return cmd
}

func newAnalyticsRiskCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk trend: average/max score and critical/high counts over time",
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Risk(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "Trend (bucket, avg, max, critical, high):") //nolint:errcheck
		for _, b := range result.Trend {
			fmt.Fprintf(w, "  %s\t%.1f\t%d\t%d\t%d\n", b.BucketStart.Format(time.RFC3339), b.AverageScore, b.MaxScore, b.CriticalCount, b.HighCount) //nolint:errcheck
		}
		printNamedCounts(w, "\nLatest Distribution", result.Distribution)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsAlertsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "alerts", Short: "Alert analytics: over time, by severity, status, and rule"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Alerts(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		printBuckets(w, "Over Time", result.OverTime)
		printNamedCounts(w, "By Severity", result.BySeverity)
		printNamedCounts(w, "By Status", result.ByStatus)
		printNamedCounts(w, "By Rule", result.ByRule)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsDetectionsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "detections", Short: "Detection analytics: matches, rule inventory, noisiest rules"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Detections(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Enabled Rules:\t%d\n", result.EnabledRules)   //nolint:errcheck
		fmt.Fprintf(w, "Disabled Rules:\t%d\n", result.DisabledRules) //nolint:errcheck
		printBuckets(w, "\nMatches Over Time", result.MatchesOverTime)
		printNamedCounts(w, "By Rule", result.ByRule)
		printNamedCounts(w, "By Severity", result.BySeverity)
		fmt.Fprintln(w, "\nNoisiest Rules (matches, alert conversion, dismissal rate):") //nolint:errcheck
		for _, rr := range result.NoisyRules {
			fmt.Fprintf(w, "  %s\t%d\t%.0f%%\t%.0f%%\n", rr.Rule, rr.Matches, rr.AlertConversion*100, rr.DismissalRate*100) //nolint:errcheck
		}
		return w.Flush()
	}
	return cmd
}

func newAnalyticsFindingsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "findings", Short: "Finding analytics: by severity, category, over time, top affected assets"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Findings(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Open:\t%d\n", result.Open)         //nolint:errcheck
		fmt.Fprintf(w, "Resolved:\t%d\n", result.Resolved) //nolint:errcheck
		printBuckets(w, "\nOver Time", result.OverTime)
		printNamedCounts(w, "By Severity", result.BySeverity)
		printNamedCounts(w, "By Category", result.ByCategory)
		printNamedCounts(w, "Top Affected Assets", result.AffectedAssets)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsAssetsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "assets", Short: "Asset analytics: counts, by type/status, risk"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		result, err := svc.Assets(cmd.Context(), targetID)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Total:\t%d\n", result.Total)                //nolint:errcheck
		fmt.Fprintf(w, "Critical Risk:\t%d\n", result.RiskCritical) //nolint:errcheck
		fmt.Fprintf(w, "High Risk:\t%d\n", result.RiskHigh)         //nolint:errcheck
		printNamedCounts(w, "\nBy Type", result.ByType)
		printNamedCounts(w, "By Status", result.ByStatus)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsAttackSurfaceCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "attack-surface", Short: "Attack-surface trend: new/removed assets, composition"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.AttackSurface(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Removed/Retired in range:\t%d\n", result.RemovedAssets) //nolint:errcheck
		printBuckets(w, "\nNew Assets Over Time", result.NewAssets)
		printNamedCounts(w, "By Type", result.ByType)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsCorrelationsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "correlations", Short: "Correlation analytics: over time, by severity/confidence/status/strategy"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Correlations(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		printBuckets(w, "Over Time", result.OverTime)
		printNamedCounts(w, "By Severity", result.BySeverity)
		printNamedCounts(w, "By Confidence", result.ByConfidence)
		printNamedCounts(w, "By Status", result.ByStatus)
		printNamedCounts(w, "By Strategy", result.ByStrategy)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsAttackChainsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "attack-chains", Short: "Attack chain analytics: over time, by severity/confidence, common stages"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.AttackChains(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		printBuckets(w, "Over Time", result.OverTime)
		printNamedCounts(w, "By Severity", result.BySeverity)
		printNamedCounts(w, "By Confidence", result.ByConfidence)
		printNamedCounts(w, "Common Stages", result.CommonStages)
		fmt.Fprintln(w, "\nNote: an attack chain is a correlated-evidence narrative, never proof of a confirmed attack.") //nolint:errcheck
		return w.Flush()
	}
	return cmd
}

func newAnalyticsInvestigationsCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "investigations", Short: "Investigation/incident analytics: opened/closed, duration, by severity/status"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.Investigations(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Active:\t%d\n", result.Active)                                                                            //nolint:errcheck
		fmt.Fprintf(w, "Closed in range:\t%d\n", result.ClosedCount)                                                              //nolint:errcheck
		fmt.Fprintf(w, "Mean Duration (closed, in range):\t%s\n", time.Duration(result.MeanDurationSeconds*float64(time.Second))) //nolint:errcheck
		printBuckets(w, "\nOpened Over Time", result.OpenedOverTime)
		printBuckets(w, "Closed Over Time", result.ClosedOverTime)
		printNamedCounts(w, "By Severity", result.BySeverity)
		printNamedCounts(w, "By Status", result.ByStatus)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsIntelligenceCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "intelligence", Short: "Threat intelligence analytics: by indicator type/provider/confidence, expired"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		result, err := svc.Intelligence(cmd.Context(), targetID)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Total:\t%d\n", result.Total)     //nolint:errcheck
		fmt.Fprintf(w, "Expired:\t%d\n", result.Expired) //nolint:errcheck
		printNamedCounts(w, "\nBy Indicator Type", result.ByIndicatorType)
		printNamedCounts(w, "By Provider (source)", result.ByProvider)
		printNamedCounts(w, "By Confidence", result.ByConfidence)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsAICommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{Use: "ai", Short: "AI copilot usage analytics: requests, latency, tokens, failures, tool calls"}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		result, err := svc.AI(cmd.Context(), targetID, r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Average Latency:\t%.0fms\n", result.AverageLatencyMS) //nolint:errcheck
		fmt.Fprintf(w, "Input Tokens:\t%d\n", result.InputTokens)             //nolint:errcheck
		fmt.Fprintf(w, "Output Tokens:\t%d\n", result.OutputTokens)           //nolint:errcheck
		fmt.Fprintf(w, "Failures:\t%d\n", result.Failures)                    //nolint:errcheck
		printBuckets(w, "\nRequests Over Time", result.RequestsOverTime)
		printNamedCounts(w, "By Task Type", result.ByTaskType)
		printNamedCounts(w, "By Provider", result.ByProvider)
		printNamedCounts(w, "Tool Calls By Tool", result.ToolCallsByTool)
		return w.Flush()
	}
	return cmd
}

func newAnalyticsPostureCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Security posture score — derived from existing risk data, never an objective measure of security",
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		p, err := svc.Posture(cmd.Context(), targetID)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "Score:\t%.0f/100\n", p.Score)                                                             //nolint:errcheck
		fmt.Fprintf(w, "Scored Entities:\t%d\n", p.ScoredEntities)                                                //nolint:errcheck
		fmt.Fprintf(w, "Critical:\t%d\n", p.CriticalCount)                                                        //nolint:errcheck
		fmt.Fprintf(w, "High:\t%d\n", p.HighCount)                                                                //nolint:errcheck
		fmt.Fprintln(w, "\nSee docs/analytics/metrics.md for the exact calculation, weighting, and limitations.") //nolint:errcheck
		return w.Flush()
	}
	return cmd
}

func newAnalyticsTimeSeriesCommand() *cobra.Command {
	var targetValue, targetType, metric string
	cmd := &cobra.Command{
		Use:   "timeseries",
		Short: fmt.Sprintf("A single validated time series. --metric must be one of: %v", analytics.ValidMetrics()),
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&metric, "metric", "", "required — see command help for the valid list")
	rf := addRangeFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if metric == "" {
			return fmt.Errorf("--metric is required — one of %v", analytics.ValidMetrics())
		}
		svc, db, err := buildAnalyticsService(cmd)
		if err != nil {
			return err
		}
		defer db.Close()
		targetID, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
		if err != nil {
			return err
		}
		r, err := rf.resolve()
		if err != nil {
			return err
		}
		buckets, err := svc.TimeSeries(cmd.Context(), targetID, analytics.Metric(metric), r)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		printBuckets(w, metric, buckets)
		return w.Flush()
	}
	return cmd
}
