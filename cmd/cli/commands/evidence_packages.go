package commands

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// NewEvidencePackageCommand returns the `ai-recon evidence-package`
// command group (phase14.md §45/§46/§47) — always scoped to one
// already-generated report's own cited evidence, never a dump of an
// entire target's data.
func NewEvidencePackageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence-package",
		Short: "Create and inspect evidence export packages for a report",
	}
	cmd.AddCommand(newEvidencePackageCreateCommand())
	cmd.AddCommand(newEvidencePackageShowCommand())
	cmd.AddCommand(newEvidencePackageManifestCommand())
	return cmd
}

func newEvidencePackageCreateCommand() *cobra.Command {
	var reportIDStr, actor string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an evidence package from an already-generated report",
		RunE: func(cmd *cobra.Command, _ []string) error {
			reportID, err := uuid.Parse(reportIDStr)
			if err != nil {
				return fmt.Errorf("invalid --report: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			pkg, manifest, err := svc.CreateEvidencePackage(cmd.Context(), reportID, actor)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Package %s created with %d evidence item(s).\n", pkg.ID, len(manifest)) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&reportIDStr, "report", "", "report id to build the package from (required)")
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	return cmd
}

func newEvidencePackageShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <package-id>",
		Short: "Show an evidence package's own metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid package id: %w", err)
			}
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			pkg, err := svc.GetPackage(cmd.Context(), id)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "ID:\t%s\n", pkg.ID)           //nolint:errcheck
			fmt.Fprintf(w, "Target:\t%s\n", pkg.TargetID) //nolint:errcheck
			if pkg.ReportID != nil {
				fmt.Fprintf(w, "Report:\t%s\n", *pkg.ReportID) //nolint:errcheck
			}
			fmt.Fprintf(w, "Created By:\t%s\n", pkg.CreatedBy)                      //nolint:errcheck
			fmt.Fprintf(w, "Created At:\t%s\n", pkg.CreatedAt.Format(time.RFC3339)) //nolint:errcheck
			return w.Flush()
		},
	}
	return cmd
}

func newEvidencePackageManifestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest <package-id>",
		Short: "Show an evidence package's manifest — item id, type, hash, timestamp",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid package id: %w", err)
			}
			svc, db, err := buildReportingService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			items, err := svc.GetManifest(cmd.Context(), id)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ITEM ID\tTYPE\tREFERENCE\tHASH\tTIMESTAMP") //nolint:errcheck
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", item.ID, item.ItemType, item.ReferenceID, item.Hash, item.Timestamp.Format(time.RFC3339)) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}
