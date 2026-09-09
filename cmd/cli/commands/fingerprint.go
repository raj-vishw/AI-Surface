package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-surface-platform/internal/config"
	"ai-surface-platform/internal/database"
	domaintarget "ai-surface-platform/internal/domain/target"
	fpengine "ai-surface-platform/internal/fingerprint"
	"ai-surface-platform/internal/logging"
	assetsvc "ai-surface-platform/internal/service/asset"
	fingerprintsvc "ai-surface-platform/internal/service/fingerprint"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewFingerprintCommand returns the `ai-surface fingerprint` command —
// Phase 6's passive technology-fingerprinting entry point. It analyzes
// evidence Phase 3/4/5 already collected and persisted; it never
// performs a fresh network/DNS request itself, even when invoked
// (phase6.md §25/§26/§46) — running it twice against unchanged data
// produces the same current-state result, not a re-scan.
func NewFingerprintCommand() *cobra.Command {
	var (
		targetValue   string
		targetType    string
		assetIDStr    string
		scanIDStr     string
		format        string
		minConfidence float64
		category      string
		explain       bool
		dryRun        bool
	)

	cmd := &cobra.Command{
		Use:   "fingerprint --target <target> | --asset <asset-id>",
		Short: "Passively identify technologies from already-collected evidence",
		Long: "Runs the passive fingerprinting engine against evidence the HTTP, network, and DNS\n" +
			"discovery engines already collected and persisted. It performs no network or\n" +
			"DNS request of its own — analyzing an asset that was never actually scanned produces no\n" +
			"fingerprints, not an error. Exactly one of --target or --asset is required.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (targetValue == "") == (assetIDStr == "") {
				return fmt.Errorf("exactly one of --target or --asset is required")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Fingerprint.Enabled {
				return fmt.Errorf("fingerprint.enabled is false in the effective configuration")
			}
			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("min-confidence") {
				cfg.Fingerprint.MinConfidence = minConfidence
			}

			var scanID *uuid.UUID
			if scanIDStr != "" {
				id, err := uuid.Parse(scanIDStr)
				if err != nil {
					return fmt.Errorf("invalid --scan: %w", err)
				}
				scanID = &id
			} else {
				id := uuid.New()
				scanID = &id
			}

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

			engine, err := buildEngine(cfg)
			if err != nil {
				return fmt.Errorf("loading fingerprint signatures: %w", err)
			}

			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			fingerprints := fingerprintsvc.NewService(db, assets, engine, logger, fingerprintsvc.Config{
				ConfidenceChangeThreshold: cfg.Fingerprint.ConfidenceChangeThreshold,
			})

			var analyses []*fingerprintsvc.AnalysisResult
			if assetIDStr != "" {
				id, err := uuid.Parse(assetIDStr)
				if err != nil {
					return fmt.Errorf("invalid --asset: %w", err)
				}
				result, err := fingerprints.Analyze(ctx, id, scanID, cfg.Security.DryRun)
				if err != nil {
					return err
				}
				analyses = []*fingerprintsvc.AnalysisResult{result}
			} else {
				resolvedType := domaintarget.Type(strings.ToUpper(targetType))
				if resolvedType == "" {
					resolvedType = domaintarget.TypeDomain
				}
				target, err := targets.GetByValue(ctx, resolvedType, targetValue)
				if err != nil {
					return fmt.Errorf("loading target: %w", err)
				}
				analyses, err = fingerprints.AnalyzeTarget(ctx, target.ID, scanID, cfg.Security.DryRun)
				if err != nil {
					return err
				}
			}

			results := filterResults(analyses, category, minConfidenceOrDefault(cmd, minConfidence, cfg.Fingerprint.MinConfidence))

			if format == "json" {
				return printFingerprintJSON(cmd, results)
			}
			return printFingerprintTable(cmd, results, explain, cfg.Security.DryRun)
		},
	}

	cmd.Flags().StringVar(&targetValue, "target", "", "analyze every asset belonging to this target")
	cmd.Flags().StringVar(&targetType, "target-type", "", "DOMAIN|HOST|IP|URL — defaults to DOMAIN (only used with --target)")
	cmd.Flags().StringVar(&assetIDStr, "asset", "", "analyze exactly this asset (UUID)")
	cmd.Flags().StringVar(&scanIDStr, "scan", "", "attribute persisted fingerprints to this scan id (UUID) — defaults to a freshly generated one")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().Float64Var(&minConfidence, "min-confidence", 0, "override fingerprint.min_confidence — hide results below this score")
	cmd.Flags().StringVar(&category, "category", "", "show only results in this category (e.g. web_server, framework, ai_provider)")
	cmd.Flags().BoolVar(&explain, "explain", false, "show the supporting signals behind each fingerprint")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — evaluate without persisting anything")

	return cmd
}

func minConfidenceOrDefault(cmd *cobra.Command, flagValue, configValue float64) float64 {
	if cmd.Flags().Changed("min-confidence") {
		return flagValue
	}
	return configValue
}

// buildEngine loads the configured signature set (the built-in one
// unless fingerprint.signatures_path names an external directory) and
// builds the matching engine with the configured thresholds.
func buildEngine(cfg *config.Config) (*fpengine.Engine, error) {
	var (
		sigs []fpengine.CompiledSignature
		err  error
	)
	if cfg.Fingerprint.SignaturesPath != "" {
		sigs, err = fpengine.LoadSignatures(os.DirFS(cfg.Fingerprint.SignaturesPath))
	} else {
		sigs, err = fpengine.LoadDefaultSignatures()
	}
	if err != nil {
		return nil, err
	}

	thresholds := fpengine.Thresholds{
		Low: cfg.Fingerprint.Thresholds.Low, Medium: cfg.Fingerprint.Thresholds.Medium,
		High: cfg.Fingerprint.Thresholds.High, VeryHigh: cfg.Fingerprint.Thresholds.VeryHigh,
	}
	return fpengine.NewEngine(sigs, fpengine.EngineConfig{
		MinConfidence: cfg.Fingerprint.MinConfidence, Thresholds: thresholds,
	}), nil
}

func filterResults(analyses []*fingerprintsvc.AnalysisResult, category string, minConfidence float64) []*fingerprintsvc.AnalysisResult {
	if category == "" && minConfidence <= 0 {
		return analyses
	}
	out := make([]*fingerprintsvc.AnalysisResult, 0, len(analyses))
	for _, a := range analyses {
		var kept []fpengine.Result
		for _, r := range a.Results {
			if category != "" && string(r.Category) != category {
				continue
			}
			if r.Confidence < minConfidence {
				continue
			}
			kept = append(kept, r)
		}
		out = append(out, &fingerprintsvc.AnalysisResult{Asset: a.Asset, Results: kept, Changes: a.Changes})
	}
	return out
}

func assetLabel(a fingerprintsvc.AnalysisResult) string {
	switch {
	case a.Asset.URL != nil && *a.Asset.URL != "":
		return *a.Asset.URL
	case a.Asset.Hostname != nil && *a.Asset.Hostname != "":
		return *a.Asset.Hostname
	case a.Asset.IP != nil && *a.Asset.IP != "":
		return *a.Asset.IP
	default:
		return a.Asset.ID.String()
	}
}

// errWriter accumulates the first write error across many Fprint* calls
// so callers can write a straight-line sequence of prints (readable, and
// every error is still checked — errcheck-clean — via the single err
// return at the end) instead of an `if err != nil { return err }` after
// every single line.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

func printFingerprintTable(cmd *cobra.Command, analyses []*fingerprintsvc.AnalysisResult, explain, dryRun bool) error {
	ew := &errWriter{w: cmd.OutOrStdout()}
	if dryRun {
		ew.printf("DRY RUN — nothing persisted\n\n")
	}
	for _, a := range analyses {
		ew.printf("Asset: %s\n\n", assetLabel(*a))
		if len(a.Results) == 0 {
			ew.printf("(no fingerprints matched)\n\n")
			continue
		}

		w := tabwriter.NewWriter(ew.w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TECHNOLOGY\tCATEGORY\tVERSION\tCONFIDENCE\tLEVEL") //nolint:errcheck // tabwriter buffers; the real write happens (and is checked) at Flush
		for _, r := range a.Results {
			version := r.Version
			if version == "" {
				version = "unknown"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\n", r.Technology, r.Category, version, r.Confidence, r.Level) //nolint:errcheck // see above
		}
		if err := w.Flush(); err != nil && ew.err == nil {
			ew.err = err
		}

		if explain {
			ew.printf("\n")
			for _, r := range a.Results {
				ew.printf("%s (confidence %.2f):\n", r.Technology, r.Confidence)
				for _, s := range r.Signals {
					ew.printf("  + %s\n", s.Description)
				}
			}
		}

		if len(a.Changes) > 0 {
			ew.printf("\nChanges since previous analysis:\n")
			for _, c := range a.Changes {
				ew.printf("  %s: %s (%s)\n", c.Type, c.Technology, c.Category)
			}
		}
		ew.printf("\n")
	}
	return ew.err
}

// jsonFingerprint / jsonSignal / jsonAssetResult mirror phase6.md §27's
// worked JSON example exactly.
type jsonSignal struct {
	Type  string `json:"type"`
	Field string `json:"field"`
	Value string `json:"value"`
}
type jsonFingerprint struct {
	Technology string       `json:"technology"`
	Category   string       `json:"category"`
	Vendor     string       `json:"vendor,omitempty"`
	Version    string       `json:"version"`
	Confidence float64      `json:"confidence"`
	Level      string       `json:"level"`
	Signals    []jsonSignal `json:"signals"`
}
type jsonAssetResult struct {
	Asset        string            `json:"asset"`
	Fingerprints []jsonFingerprint `json:"fingerprints"`
}

func printFingerprintJSON(cmd *cobra.Command, analyses []*fingerprintsvc.AnalysisResult) error {
	out := make([]jsonAssetResult, len(analyses))
	for i, a := range analyses {
		fps := make([]jsonFingerprint, len(a.Results))
		for j, r := range a.Results {
			signals := make([]jsonSignal, len(r.Signals))
			for k, s := range r.Signals {
				signals[k] = jsonSignal{Type: string(s.Type), Field: s.Field, Value: s.Value}
			}
			version := r.Version
			if version == "" {
				version = "unknown"
			}
			fps[j] = jsonFingerprint{
				Technology: r.Technology, Category: string(r.Category), Vendor: r.Vendor,
				Version: version, Confidence: r.Confidence, Level: string(r.Level), Signals: signals,
			}
		}
		out[i] = jsonAssetResult{Asset: assetLabel(*a), Fingerprints: fps}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if len(out) == 1 {
		return enc.Encode(out[0])
	}
	return enc.Encode(out)
}
