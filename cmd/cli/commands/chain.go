package commands

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	"ai-surface-platform/internal/repository/pagination"
)

// NewChainCommand returns the `ai-surface chain` command group — Phase
// 12's attack-chain read surface. A chain is a narrative representation
// of correlated activity, never itself proof of an attack (phase12.md
// §40).
func NewChainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Inspect attack chains — narrative summaries of correlated activity",
	}
	cmd.AddCommand(newChainListCommand())
	cmd.AddCommand(newChainShowCommand())
	cmd.AddCommand(newChainExplainCommand())
	return cmd
}

func newChainListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List attack chains",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			page, err := svc.ListChains(cmd.Context(), pagination.Params{Limit: pagination.MaxLimit})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tCORRELATION\tNAME\tSEVERITY\tCONFIDENCE\tSTATUS") //nolint:errcheck
			for _, c := range page.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.CorrelationID, c.Name, c.Severity, c.Confidence, c.Status) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newChainShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one attack chain and its stages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid chain id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			chain, stages, err := svc.GetChainByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			return printChain(cmd, chain, stages)
		},
	}
	return cmd
}

func newChainExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <id>",
		Short: "Explain an attack chain — confidence, timeline, and evidence counts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid chain id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			chain, stages, err := svc.GetChainByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			if err := printChain(cmd, chain, stages); err != nil {
				return err
			}

			c, err := svc.GetCorrelation(cmd.Context(), chain.CorrelationID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nExplanation:\n%s\n", c.Description) //nolint:errcheck
			return nil
		},
	}
	return cmd
}

// printChain renders one attack chain (Attack Chain / Confidence /
// Severity / Timeline / Evidence — the exact shape phase12.md §56's
// worked "ai-surface chain show" example uses). It is a representation of
// correlated activity, never itself asserted as proof of an attack.
func printChain(cmd *cobra.Command, chain domaincorrelation.AttackChain, stages []domaincorrelation.AttackChainStage) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Attack Chain:\t%s\n", chain.Name)     //nolint:errcheck
	fmt.Fprintf(w, "Confidence:\t%s\n", chain.Confidence) //nolint:errcheck
	fmt.Fprintf(w, "Severity:\t%s\n", chain.Severity)     //nolint:errcheck
	fmt.Fprintf(w, "Status:\t%s\n", chain.Status)         //nolint:errcheck
	fmt.Fprintln(w, "\nTimeline:")                        //nolint:errcheck
	evidenceCount := map[domaincorrelation.NodeType]int{}
	for _, s := range stages {
		fmt.Fprintf(w, "    Stage %d:\t%s (%s confidence, %d evidence item(s))\n", s.Order+1, s.Stage, s.Confidence, len(s.Evidence)) //nolint:errcheck
		for _, ev := range s.Evidence {
			evidenceCount[ev.NodeType]++
		}
	}
	fmt.Fprintln(w, "\nEvidence:") //nolint:errcheck
	for nodeType, count := range evidenceCount {
		fmt.Fprintf(w, "    %d %s(s)\n", count, nodeType) //nolint:errcheck
	}
	fmt.Fprintf(w, "\nGenerated:\t%s\n", chain.CreatedAt.Format(time.RFC3339)) //nolint:errcheck
	return w.Flush()
}
