package commands

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	domainintel "ai-surface-platform/internal/domain/intelligence"
	"ai-surface-platform/internal/repository/pagination"
	intelligencesvc "ai-surface-platform/internal/service/intelligence"
)

// NewRiskCommand returns the `ai-surface risk` command group — Phase 10's
// risk-scoring entry point. A risk score is always a combined security
// context signal, never a claim of confirmed vulnerability (phase10.md
// §35); every score prints the factors that produced it.
func NewRiskCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Calculate and inspect risk scores for assets, findings, and investigations",
	}
	cmd.AddCommand(newRiskAssetCommand())
	cmd.AddCommand(newRiskFindingCommand())
	cmd.AddCommand(newRiskInvestigationCommand())
	cmd.AddCommand(newRiskCriticalityCommand())
	return cmd
}

func printRiskScore(cmd *cobra.Command, label string, score domainintel.RiskScore, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(score)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "%s Risk\n\n", label)                                                      //nolint:errcheck
	fmt.Fprintf(w, "Risk Score:\t%d / 100\n", score.Score)                                    //nolint:errcheck
	fmt.Fprintf(w, "Severity:\t%s\n", score.Severity)                                         //nolint:errcheck
	fmt.Fprintf(w, "Confidence:\t%s\n", score.Confidence)                                     //nolint:errcheck
	fmt.Fprintf(w, "Model:\t%s\n", score.ModelVersion)                                        //nolint:errcheck
	fmt.Fprintf(w, "Calculated At:\t%s\n", score.CalculatedAt.Format("2006-01-02T15:04:05Z")) //nolint:errcheck
	fmt.Fprintln(w, "")                                                                       //nolint:errcheck
	fmt.Fprintln(w, "Factors:")                                                               //nolint:errcheck
	for _, f := range score.Factors {
		sign := "+"
		if f.Points < 0 {
			sign = ""
		}
		fmt.Fprintf(w, "  %s:\t%s%d\n", f.Description, sign, f.Points) //nolint:errcheck
	}
	return w.Flush()
}

func newRiskAssetCommand() *cobra.Command {
	var jsonOut, history bool
	cmd := &cobra.Command{
		Use:   "asset <asset-id>",
		Short: "Calculate (or show the history of) an asset's risk score",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			assetID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid asset id: %w", err)
			}
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if history {
				return printRiskHistory(cmd, svc, domainintel.EntityAsset, assetID, jsonOut)
			}
			enrichment, err := svc.EnrichAsset(cmd.Context(), assetID)
			if err != nil {
				return err
			}
			return printRiskScore(cmd, "Asset", enrichment.Risk, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.Flags().BoolVar(&history, "history", false, "show risk score history instead of recalculating")
	return cmd
}

func newRiskFindingCommand() *cobra.Command {
	var jsonOut, history bool
	cmd := &cobra.Command{
		Use:   "finding <finding-id>",
		Short: "Calculate (or show the history of) a finding's risk score",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findingID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid finding id: %w", err)
			}
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if history {
				return printRiskHistory(cmd, svc, domainintel.EntityFinding, findingID, jsonOut)
			}
			enrichment, err := svc.EnrichFinding(cmd.Context(), findingID)
			if err != nil {
				return err
			}
			return printRiskScore(cmd, "Finding", enrichment.Risk, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.Flags().BoolVar(&history, "history", false, "show risk score history instead of recalculating")
	return cmd
}

func newRiskInvestigationCommand() *cobra.Command {
	var jsonOut, history bool
	cmd := &cobra.Command{
		Use:   "investigation <investigation-id>",
		Short: "Calculate (or show the history of) an investigation's aggregate risk score",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			investigationID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if history {
				return printRiskHistory(cmd, svc, domainintel.EntityInvestigation, investigationID, jsonOut)
			}
			enrichment, err := svc.EnrichInvestigation(cmd.Context(), investigationID)
			if err != nil {
				return err
			}
			return printRiskScore(cmd, "Investigation", enrichment.Risk, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON")
	cmd.Flags().BoolVar(&history, "history", false, "show risk score history instead of recalculating")
	return cmd
}

func printRiskHistory(cmd *cobra.Command, svc *intelligencesvc.Service, entityType domainintel.EntityType, entityID uuid.UUID, jsonOut bool) error {
	page, err := svc.RiskHistory(cmd.Context(), entityType, entityID, pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(page.Items)
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CALCULATED AT\tSCORE\tSEVERITY\tMODEL") //nolint:errcheck
	for _, s := range page.Items {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", s.CalculatedAt.Format("2006-01-02T15:04:05Z"), s.Score, s.Severity, s.ModelVersion) //nolint:errcheck
	}
	return w.Flush()
}

func newRiskCriticalityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "criticality",
		Short: "Set an asset's analyst-assigned criticality (never inferred automatically)",
	}
	cmd.AddCommand(newRiskCriticalitySetCommand())
	return cmd
}

func newRiskCriticalitySetCommand() *cobra.Command {
	var level, setBy string
	cmd := &cobra.Command{
		Use:   "set <asset-id>",
		Short: "Set an asset's criticality: low|normal|high|critical",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			assetID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid asset id: %w", err)
			}
			if level == "" || setBy == "" {
				return fmt.Errorf("--level and --set-by are both required")
			}
			svc, db, err := buildIntelligenceService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			asset, err := svc.GetAsset(cmd.Context(), assetID)
			if err != nil {
				return err
			}
			result, err := svc.SetCriticality(cmd.Context(), assetID, asset.TargetID, domainintel.Criticality(level), setBy)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Asset %s criticality set to %s by %s.\n", result.AssetID, result.Criticality, result.SetBy)
			return nil
		},
	}
	cmd.Flags().StringVar(&level, "level", "", "low|normal|high|critical (required)")
	cmd.Flags().StringVar(&setBy, "set-by", "", "analyst identifier (required)")
	return cmd
}
