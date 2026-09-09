package commands

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	domainreporting "ai-surface-platform/internal/domain/reporting"
	"ai-surface-platform/internal/repository/pagination"
	reportingrepo "ai-surface-platform/internal/repository/reporting"
)

// NewControlCommand returns the `ai-surface control` command group
// (phase14.md §50/§51/§52) — a generic, framework-agnostic evidence
// ledger. No compliance framework is hard-coded (none already exists in
// this project — phase14.md §50's own instruction), and this platform
// never claims "compliant" anywhere in this command's output.
func NewControlCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Record and review generic control evidence — never a compliance certification",
	}
	cmd.AddCommand(newControlRecordCommand())
	cmd.AddCommand(newControlListCommand())
	cmd.AddCommand(newControlEvidenceCommand())
	return cmd
}

func newControlRecordCommand() *cobra.Command {
	var targetValue, targetType, controlID, evidenceType, referenceIDStr, description, collectedAtStr string
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Record one piece of evidence for a control — an explicit analyst action",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			target, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
			if err != nil {
				return err
			}
			refID, err := uuid.Parse(referenceIDStr)
			if err != nil {
				return fmt.Errorf("invalid --reference: %w", err)
			}
			collectedAt := time.Now()
			if collectedAtStr != "" {
				collectedAt, err = time.Parse(time.RFC3339, collectedAtStr)
				if err != nil {
					return fmt.Errorf("invalid --collected-at: %w", err)
				}
			}

			c, err := svc.RecordControlEvidence(cmd.Context(), domainreporting.ControlEvidence{
				TargetID: target, ControlID: controlID, EvidenceType: domainreporting.EvidenceItemType(evidenceType),
				ReferenceID: refID, Description: description, CollectedAt: collectedAt,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Recorded control evidence %s for control %q.\n", c.ID, c.ControlID) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&controlID, "control", "", "analyst-defined control identifier (required)")
	cmd.Flags().StringVar(&evidenceType, "evidence-type", "", "finding|alert|detection_match|correlation|investigation|intelligence_record|asset|event (required)")
	cmd.Flags().StringVar(&referenceIDStr, "reference", "", "id of the referenced evidence item (required)")
	cmd.Flags().StringVar(&description, "description", "", "why this evidence relates to the control (required)")
	cmd.Flags().StringVar(&collectedAtStr, "collected-at", "", "RFC3339 (defaults to now)")
	return cmd
}

func newControlListCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every control with recorded evidence, and its freshness — a control with no evidence never appears (a gap, by absence)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			target, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
			if err != nil {
				return err
			}
			dashboard, err := svc.ControlDashboard(cmd.Context(), target)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CONTROL\tEVIDENCE COUNT\tMOST RECENT") //nolint:errcheck
			for _, c := range dashboard {
				fmt.Fprintf(w, "%s\t%d\t%s\n", c.ControlID, c.EvidenceCount, c.MostRecentAt.Format(time.RFC3339)) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	return cmd
}

func newControlEvidenceCommand() *cobra.Command {
	var targetValue, targetType, controlID string
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "List the individual evidence records for one control",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if controlID == "" {
				return fmt.Errorf("--control is required")
			}
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			target, err := resolveAnalyticsTarget(cmd, db, targetValue, targetType)
			if err != nil {
				return err
			}
			items, err := svc.ListControlEvidence(cmd.Context(), reportingrepo.ControlEvidenceListFilter{
				TargetID: target, ControlID: controlID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
			})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tREFERENCE\tCOLLECTED AT\tDESCRIPTION") //nolint:errcheck
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.EvidenceType, item.ReferenceID, item.CollectedAt.Format(time.RFC3339), item.Description) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "target (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&controlID, "control", "", "control identifier (required)")
	return cmd
}
