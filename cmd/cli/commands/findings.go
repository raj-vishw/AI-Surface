package commands

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	detectionengine "ai-recon-platform/internal/detection"
	"ai-recon-platform/internal/detection/detectors"
	domainfinding "ai-recon-platform/internal/domain/finding"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/logging"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
	assetsvc "ai-recon-platform/internal/service/asset"
	detectionsvc "ai-recon-platform/internal/service/detection"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewFindingsCommand returns the `ai-recon findings` command group —
// Phase 8's finding/vulnerability detection entry point: it transforms
// evidence Phase 2-7 already collected into structured, evidence-backed,
// lifecycle-tracked findings. It defaults to passive analysis (no network
// request of its own); safe-active mode issues a small, bounded set of
// additional requests only against already-known/well-known paths, and
// only against an AUTHORIZED target (phase8.md §13/§54/§84).
func NewFindingsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Detect, list, and manage security findings derived from already-collected evidence",
	}
	cmd.AddCommand(newFindingsScanCommand())
	cmd.AddCommand(newFindingsListCommand())
	cmd.AddCommand(newFindingsShowCommand())
	cmd.AddCommand(newFindingsDiffCommand())
	return cmd
}

// buildDetectionRegistry registers every built-in detector. catalog is
// nil (the default, empty VulnerabilityCatalog — phase8.md §41) until a
// future feed-loading mechanism exists.
func buildDetectionRegistry() (*detectionengine.Registry, error) {
	registry := detectionengine.NewRegistry()
	if err := detectors.RegisterAll(registry, nil); err != nil {
		return nil, fmt.Errorf("registering detectors: %w", err)
	}
	return registry, nil
}

func newFindingsScanCommand() *cobra.Command {
	var (
		targetType string
		mode       string
		scanIDStr  string
		format     string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "scan --target <target>",
		Short: "Run finding detection against a target's already-collected evidence",
		Long: "Analyzes every HTTP/API/AI-endpoint asset already known for --target using Phase 8's\n" +
			"detector set. Defaults to passive analysis (detection.mode / --mode passive): no network\n" +
			"request of its own. --mode safe_active additionally allows a small set of bounded,\n" +
			"already-known-path requests (e.g. re-checking an already-observed error page, or a fixed\n" +
			"well-known path like /.git/HEAD) — and requires the target be AUTHORIZED, exactly like\n" +
			"every other active discovery command in this project.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("--target is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Detection.Enabled {
				return fmt.Errorf("detection.enabled is false in the effective configuration")
			}
			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("mode") {
				cfg.Detection.Mode = mode
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration after flag overrides: %w", err)
			}

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = domaintarget.TypeDomain
			}

			var scanID *uuid.UUID
			if scanIDStr != "" {
				id, err := uuid.Parse(scanIDStr)
				if err != nil {
					return fmt.Errorf("invalid --scan: %w", err)
				}
				scanID = &id
			}

			logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})

			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			registry, err := buildDetectionRegistry()
			if err != nil {
				return err
			}

			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			fingerprints := fingerprintrepo.NewPostgresRepository(db)
			svc := detectionsvc.NewService(db, targets, assets, fingerprints, registry, logger)

			detCfg := detectionEngineConfig(cfg)
			modeValue := detectionengine.Mode(cfg.Detection.Mode)
			if modeValue == "" {
				modeValue = detectionengine.ModePassive
			}

			result, dryRunReport, err := svc.Run(ctx, detectionsvc.Request{
				TargetType: resolvedType, TargetValue: target, Mode: modeValue,
				ScanID: scanID, DryRun: cfg.Security.DryRun, Config: detCfg,
			})
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				return printFindingsDryRun(cmd, dryRunReport)
			}
			if format == "json" {
				return printFindingsScanJSON(cmd, result)
			}
			return printFindingsScanTable(cmd, result)
		},
	}

	cmd.Flags().String("target", "", "the target to analyze (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&mode, "mode", "", "override detection.mode: passive|safe_active")
	cmd.Flags().StringVar(&scanIDStr, "scan", "", "attribute persisted findings to this scan id (UUID) — defaults to a freshly generated one")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — report the detection plan without persisting or requesting anything")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func detectionEngineConfig(cfg *config.Config) detectionengine.Config {
	return detectionengine.Config{
		Detectors:                 cfg.Detection.Detectors,
		MaxExcerptLength:          cfg.Detection.Evidence.MaxExcerptSize,
		CertificateExpiryWarnDays: cfg.Detection.Thresholds.CertificateExpiryDays,
		RequestTimeout:            cfg.Detection.Timeout,
		MaxResponseSize:           cfg.Detection.MaxResponseSize,
	}
}

func printFindingsDryRun(cmd *cobra.Command, report *detectionsvc.DryRunReport) error {
	out := cmd.OutOrStdout()
	_, err := fmt.Fprintf(out, "Finding Detection Plan\n\nTarget:\n    %s\n\nMode:\n    %s\n\nEnabled detectors:\n    %s\n\nNetwork requests:\n    %d\n",
		report.Target, report.Mode, strings.Join(report.EnabledDetectors, "\n    "), report.NetworkRequests)
	return err
}

func printFindingsScanTable(cmd *cobra.Command, result *detectionsvc.RunResult) error {
	ew := &errWriter{w: cmd.OutOrStdout()}
	ew.printf("Target: %s (scan %s, %d assets analyzed)\n\n", result.Target.Name, result.ScanID, result.AssetsAnalyzed)

	if len(result.Findings) == 0 {
		ew.printf("(no findings)\n")
	} else {
		w := tabwriter.NewWriter(ew.w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SEVERITY\tFINDING\tCATEGORY\tSTATUS\tCONFIDENCE") //nolint:errcheck // see fingerprint.go's identical pattern
		for _, f := range result.Findings {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.2f\n", f.Severity, f.Title, f.Category, f.Status, float64(f.Confidence)) //nolint:errcheck
		}
		if err := w.Flush(); err != nil && ew.err == nil {
			ew.err = err
		}
	}

	if len(result.Changes) > 0 {
		ew.printf("\nChanges this scan:\n")
		for _, c := range result.Changes {
			ew.printf("  %s: %s\n", c.Type, c.Title)
		}
	}
	if len(result.DetectorErrors) > 0 {
		ew.printf("\nDetector errors (partial results — other detectors still ran):\n")
		for _, e := range result.DetectorErrors {
			ew.printf("  %s: %v\n", e.DetectorID, e.Err)
		}
	}
	return ew.err
}

// jsonEvidence/jsonFinding/jsonScanResult mirror phase8.md §51's worked
// JSON example.
type jsonEvidence struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data,omitempty"`
}
type jsonReference struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}
type jsonFinding struct {
	FindingID   string          `json:"finding_id"`
	DetectorID  string          `json:"detector_id"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Category    string          `json:"category"`
	Severity    string          `json:"severity"`
	Confidence  string          `json:"confidence"`
	Asset       string          `json:"asset"`
	Endpoint    string          `json:"endpoint,omitempty"`
	Status      string          `json:"status"`
	Evidence    []jsonEvidence  `json:"evidence"`
	Remediation string          `json:"remediation,omitempty"`
	References  []jsonReference `json:"references,omitempty"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
}

func toJSONFinding(f domainfinding.Finding) jsonFinding {
	evidence := make([]jsonEvidence, 0)
	references := make([]jsonReference, 0, len(f.References))
	for _, r := range f.References {
		references = append(references, jsonReference{Label: r.Label, URL: r.URL})
	}
	endpoint := ""
	if f.EndpointID != nil {
		endpoint = f.EndpointID.String()
	}
	return jsonFinding{
		FindingID: f.ID.String(), DetectorID: f.DetectorID, Title: f.Title, Description: f.Description,
		Category: string(f.Category), Severity: string(f.Severity), Confidence: string(f.Confidence.Level()),
		Asset: f.AssetID.String(), Endpoint: endpoint, Status: string(f.Status), Evidence: evidence,
		Remediation: f.Remediation, References: references, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
	}
}

type jsonScanResult struct {
	ScanID   string        `json:"scan_id"`
	Target   string        `json:"target"`
	Findings []jsonFinding `json:"findings"`
}

func printFindingsScanJSON(cmd *cobra.Command, result *detectionsvc.RunResult) error {
	out := jsonScanResult{ScanID: result.ScanID.String(), Target: result.Target.Name, Findings: make([]jsonFinding, len(result.Findings))}
	for i, f := range result.Findings {
		out.Findings[i] = toJSONFinding(f)
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func newFindingsListCommand() *cobra.Command {
	var (
		targetType string
		severity   string
		category   string
		status     string
		detectorID string
		format     string
		limit      int
	)

	cmd := &cobra.Command{
		Use:   "list --target <target>",
		Short: "List persisted findings for a target",
		RunE: func(cmd *cobra.Command, _ []string) error {
			targetValue, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(targetValue) == "" {
				return fmt.Errorf("--target is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}

			logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			registry, err := buildDetectionRegistry()
			if err != nil {
				return err
			}
			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			fingerprints := fingerprintrepo.NewPostgresRepository(db)
			svc := detectionsvc.NewService(db, targets, assets, fingerprints, registry, logger)

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = domaintarget.TypeDomain
			}
			target, err := targets.GetByValue(ctx, resolvedType, targetValue)
			if err != nil {
				return fmt.Errorf("loading target: %w", err)
			}

			page, err := svc.List(ctx, findingrepo.ListFilter{
				TargetID: target.ID, Severity: domainfinding.Severity(severity), Category: domainfinding.Category(category),
				Status: domainfinding.Status(status), DetectorID: detectorID,
			})
			if err != nil {
				return err
			}
			items := page.Items
			if limit > 0 && len(items) > limit {
				items = items[:limit]
			}

			switch format {
			case "json":
				return printFindingsListJSON(cmd, items)
			case "csv":
				return printFindingsListCSV(cmd, items)
			default:
				return printFindingsListTable(cmd, items)
			}
		},
	}

	cmd.Flags().String("target", "", "the target whose findings to list (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity (informational|low|medium|high|critical)")
	cmd.Flags().StringVar(&category, "category", "", "filter by category")
	cmd.Flags().StringVar(&status, "status", "", "filter by status (open|resolved|reopened|accepted_risk|false_positive)")
	cmd.Flags().StringVar(&detectorID, "detector", "", "filter by detector id")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json|csv")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum findings to show (0 = no limit beyond the default page size)")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func printFindingsListTable(cmd *cobra.Command, items []domainfinding.Finding) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tFINDING\tASSET\tSTATUS\tFIRST SEEN\tLAST SEEN") //nolint:errcheck
	for _, f := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
			f.Severity, f.Title, f.AssetID, f.Status, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339))
	}
	return w.Flush()
}

func printFindingsListJSON(cmd *cobra.Command, items []domainfinding.Finding) error {
	out := make([]jsonFinding, len(items))
	for i, f := range items {
		out[i] = toJSONFinding(f)
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printFindingsListCSV(cmd *cobra.Command, items []domainfinding.Finding) error {
	w := csv.NewWriter(cmd.OutOrStdout())
	if err := w.Write([]string{"finding_id", "detector_id", "title", "category", "severity", "confidence", "status", "asset_id", "endpoint_id", "first_seen", "last_seen"}); err != nil {
		return err
	}
	for _, f := range items {
		endpoint := ""
		if f.EndpointID != nil {
			endpoint = f.EndpointID.String()
		}
		row := []string{
			f.ID.String(), f.DetectorID, f.Title, string(f.Category), string(f.Severity),
			string(f.Confidence.Level()), string(f.Status), f.AssetID.String(), endpoint,
			f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func newFindingsShowCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show <finding-id>",
		Short: "Show one finding's full detail, evidence, and lifecycle history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid finding id: %w", err)
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			registry, err := buildDetectionRegistry()
			if err != nil {
				return err
			}
			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			fingerprints := fingerprintrepo.NewPostgresRepository(db)
			svc := detectionsvc.NewService(db, targets, assets, fingerprints, registry, logger)

			f, err := svc.GetByID(ctx, id)
			if err != nil {
				return err
			}
			evidencePage, err := svc.ListEvidence(ctx, findingrepo.EvidenceListFilter{FindingID: id})
			if err != nil {
				return err
			}
			eventsPage, err := svc.ListEvents(ctx, findingrepo.EventListFilter{FindingID: id})
			if err != nil {
				return err
			}

			if format == "json" {
				return printFindingShowJSON(cmd, f, evidencePage.Items, eventsPage.Items)
			}
			return printFindingShowTable(cmd, f, evidencePage.Items, eventsPage.Items)
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func printFindingShowTable(cmd *cobra.Command, f domainfinding.Finding, evidence []domainfinding.Evidence, events []domainfinding.Event) error {
	ew := &errWriter{w: cmd.OutOrStdout()}
	ew.printf("%s\n\n", f.Title)
	ew.printf("Detector:    %s (v%d)\n", f.DetectorID, f.DetectorVersion)
	ew.printf("Category:    %s\n", f.Category)
	ew.printf("Severity:    %s", f.Severity)
	if f.SeverityOverridden {
		ew.printf(" (overridden from %s: %s)", f.DetectorSeverity, f.SeverityOverrideReason)
	}
	ew.printf("\nConfidence:  %.2f (%s)\n", float64(f.Confidence), f.Confidence.Level())
	ew.printf("Status:      %s\n", f.Status)
	ew.printf("First seen:  %s\n", f.FirstSeen.Format(time.RFC3339))
	ew.printf("Last seen:   %s\n", f.LastSeen.Format(time.RFC3339))
	ew.printf("\nDescription:\n  %s\n", f.Description)
	if f.Remediation != "" {
		ew.printf("\nRemediation:\n  %s\n", f.Remediation)
	}
	if len(evidence) > 0 {
		ew.printf("\nEvidence:\n")
		for _, e := range evidence {
			ew.printf("  [%s] %v\n", e.EvidenceType, e.EvidenceData)
		}
	}
	if len(events) > 0 {
		ew.printf("\nHistory:\n")
		for _, e := range events {
			ew.printf("  %s  %s -> %s\n", e.DetectedAt.Format(time.RFC3339), e.Type, e.ToStatus)
		}
	}
	return ew.err
}

func printFindingShowJSON(cmd *cobra.Command, f domainfinding.Finding, evidence []domainfinding.Evidence, events []domainfinding.Event) error {
	type detail struct {
		jsonFinding
		Events []struct {
			Type       string    `json:"type"`
			ToStatus   string    `json:"to_status"`
			DetectedAt time.Time `json:"detected_at"`
		} `json:"history"`
	}
	d := detail{jsonFinding: toJSONFinding(f)}
	for _, e := range evidence {
		d.Evidence = append(d.Evidence, jsonEvidence{Type: string(e.EvidenceType), Data: e.EvidenceData})
	}
	for _, ev := range events {
		d.Events = append(d.Events, struct {
			Type       string    `json:"type"`
			ToStatus   string    `json:"to_status"`
			DetectedAt time.Time `json:"detected_at"`
		}{Type: string(ev.Type), ToStatus: string(ev.ToStatus), DetectedAt: ev.DetectedAt})
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

func newFindingsDiffCommand() *cobra.Command {
	var targetType string
	cmd := &cobra.Command{
		Use:   "diff --target <target> --scan <scan-id>",
		Short: "Show which findings were new, persisting, resolved, or reopened during one scan",
		RunE: func(cmd *cobra.Command, _ []string) error {
			targetValue, _ := cmd.Flags().GetString("target")
			scanIDStr, _ := cmd.Flags().GetString("scan")
			if strings.TrimSpace(targetValue) == "" || strings.TrimSpace(scanIDStr) == "" {
				return fmt.Errorf("--target and --scan are both required")
			}
			scanID, err := uuid.Parse(scanIDStr)
			if err != nil {
				return fmt.Errorf("invalid --scan: %w", err)
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			registry, err := buildDetectionRegistry()
			if err != nil {
				return err
			}
			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			fingerprints := fingerprintrepo.NewPostgresRepository(db)
			svc := detectionsvc.NewService(db, targets, assets, fingerprints, registry, logger)

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = domaintarget.TypeDomain
			}
			target, err := targets.GetByValue(ctx, resolvedType, targetValue)
			if err != nil {
				return fmt.Errorf("loading target: %w", err)
			}

			entries, err := svc.Diff(ctx, target.ID, scanID)
			if err != nil {
				return err
			}

			ew := &errWriter{w: cmd.OutOrStdout()}
			printDiffGroup(ew, "RESOLVED", entries, "resolved")
			printDiffGroup(ew, "PERSISTING", entries, "persisting")
			printDiffGroup(ew, "REOPENED", entries, "reopened")
			printDiffGroup(ew, "NEW", entries, "new")
			return ew.err
		},
	}
	cmd.Flags().String("target", "", "the target the scan ran against (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().String("scan", "", "the scan id to diff (required)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("scan")
	return cmd
}

func printDiffGroup(ew *errWriter, label string, entries []detectionsvc.DiffEntry, changeType string) {
	ew.printf("%s:\n", label)
	found := false
	for _, e := range entries {
		if string(e.Type) != changeType {
			continue
		}
		found = true
		ew.printf("    %s\n", e.Title)
	}
	if !found {
		ew.printf("    (none)\n")
	}
	ew.printf("\n")
}
