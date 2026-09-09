package commands

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-surface-platform/internal/correlation"
	"ai-surface-platform/internal/database"
	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	domaintarget "ai-surface-platform/internal/domain/target"
	"ai-surface-platform/internal/logging"
	correlationrepo "ai-surface-platform/internal/repository/correlation"
	"ai-surface-platform/internal/repository/pagination"
	assetsvc "ai-surface-platform/internal/service/asset"
	correlationsvc "ai-surface-platform/internal/service/correlation"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewCorrelationCommand returns the `ai-surface correlation` command group
// — Phase 12's correlation engine entry point. Correlations are
// deterministic and explainable, never automatically labeled a
// "confirmed attack" (phase12.md §46); this platform implements no
// autonomous response and no offensive action of any kind.
func NewCorrelationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "correlation",
		Short: "Evaluate, inspect, and act on cross-signal correlations",
	}
	cmd.AddCommand(newCorrelationListCommand())
	cmd.AddCommand(newCorrelationShowCommand())
	cmd.AddCommand(newCorrelationEvaluateCommand())
	cmd.AddCommand(newCorrelationGraphCommand())
	cmd.AddCommand(newCorrelationTimelineCommand())
	cmd.AddCommand(newCorrelationEvidenceCommand())
	cmd.AddCommand(newCorrelationConfirmCommand())
	cmd.AddCommand(newCorrelationDismissCommand())
	cmd.AddCommand(newCorrelationMergeCommand())
	cmd.AddCommand(newCorrelationSplitCommand())
	cmd.AddCommand(newCorrelationInvestigateCommand())
	cmd.AddCommand(newCorrelationExportCommand())
	return cmd
}

// buildCorrelationService wires a *correlationsvc.Service against a
// fresh database connection. Callers must close the returned
// *database.Pool.
func buildCorrelationService(cmd *cobra.Command) (*correlationsvc.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if !cfg.Correlation.Enabled {
		return nil, nil, fmt.Errorf("correlation.enabled is false in the effective configuration")
	}

	logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
	ctx := cmd.Context()
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	engineCfg := correlation.Config{
		TemporalWindow: cfg.Correlation.Temporal.DefaultWindow,
		MaxNodes:       cfg.Correlation.Graph.MaxNodes, MaxEdges: cfg.Correlation.Graph.MaxEdges, MaxDepth: cfg.Correlation.Graph.MaxDepth,
		MaxCandidates: cfg.Correlation.MaxCandidates, HistoricalMaxRange: cfg.Correlation.HistoricalMaxRange,
	}

	targets := targetsvc.NewService(db)
	assets := assetsvc.NewService(db)
	svc := correlationsvc.NewService(db, targets, assets, engineCfg, logger)
	return svc, db, nil
}

func resolveCorrelationTargetType(raw string) domaintarget.Type {
	t := domaintarget.Type(strings.ToUpper(raw))
	if t == "" {
		return domaintarget.TypeDomain
	}
	return t
}

func printCorrelation(cmd *cobra.Command, c domaincorrelation.Correlation) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "ID:\t%s\n", c.ID)                 //nolint:errcheck
	fmt.Fprintf(w, "Title:\t%s\n", c.Title)           //nolint:errcheck
	fmt.Fprintf(w, "Status:\t%s\n", c.Status)         //nolint:errcheck
	fmt.Fprintf(w, "Severity:\t%s\n", c.Severity)     //nolint:errcheck
	fmt.Fprintf(w, "Confidence:\t%s\n", c.Confidence) //nolint:errcheck
	fmt.Fprintf(w, "Score:\t%d\n", c.Score)           //nolint:errcheck
	if c.InvestigationID != nil {
		fmt.Fprintf(w, "Investigation:\t%s\n", *c.InvestigationID) //nolint:errcheck
	}
	fmt.Fprintf(w, "First Observed:\t%s\n", c.FirstObservedAt.Format(time.RFC3339)) //nolint:errcheck
	fmt.Fprintf(w, "Last Observed:\t%s\n", c.LastObservedAt.Format(time.RFC3339))   //nolint:errcheck
	fmt.Fprintf(w, "\nDescription:\n%s\n", c.Description)                           //nolint:errcheck
	return w.Flush()
}

func newCorrelationListCommand() *cobra.Command {
	var targetValue, targetType, status string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List correlations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			filter := correlationrepo.ListFilter{Status: domaincorrelation.Status(status), Pagination: pagination.Params{Limit: pagination.MaxLimit}}
			if targetValue != "" {
				target, err := svc.ResolveTarget(cmd.Context(), resolveCorrelationTargetType(targetType), targetValue)
				if err != nil {
					return err
				}
				filter.TargetID = target.ID
			}
			page, err := svc.ListCorrelations(cmd.Context(), filter)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTITLE\tSTATUS\tSEVERITY\tCONFIDENCE\tSCORE") //nolint:errcheck
			for _, c := range page.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", c.ID, c.Title, c.Status, c.Severity, c.Confidence, c.Score) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "filter by target")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&status, "status", "", "open|investigating|confirmed|resolved|dismissed")
	return cmd
}

func newCorrelationShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one correlation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			c, err := svc.GetCorrelation(cmd.Context(), id)
			if err != nil {
				return err
			}
			return printCorrelation(cmd, c)
		},
	}
	return cmd
}

func newCorrelationEvaluateCommand() *cobra.Command {
	var targetValue, targetType, fromStr, toStr string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Run the correlation engine over a target's recent observations within [--from, --to)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" {
				return fmt.Errorf("--target is required")
			}
			to := time.Now().UTC()
			var err error
			if toStr != "" {
				to, err = time.Parse(time.RFC3339, toStr)
				if err != nil {
					return fmt.Errorf("invalid --to: %w", err)
				}
			}
			from := to.Add(-time.Hour)
			if fromStr != "" {
				from, err = time.Parse(time.RFC3339, fromStr)
				if err != nil {
					return fmt.Errorf("invalid --from: %w", err)
				}
			}

			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			target, err := svc.ResolveTarget(cmd.Context(), resolveCorrelationTargetType(targetType), targetValue)
			if err != nil {
				return err
			}

			result, err := svc.Evaluate(cmd.Context(), target.ID, from, to, dryRun)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Dry Run:\t%t\n", result.DryRun)                                 //nolint:errcheck
			fmt.Fprintf(w, "Observations Considered:\t%d\n", result.ObservationsConsidered) //nolint:errcheck
			fmt.Fprintf(w, "Components Found:\t%d\n", result.ComponentsFound)               //nolint:errcheck
			fmt.Fprintf(w, "Correlations Persisted:\t%d\n", len(result.Correlations))       //nolint:errcheck
			fmt.Fprintf(w, "Truncated:\t%t\n", result.Truncated)                            //nolint:errcheck
			fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)                              //nolint:errcheck
			for _, c := range result.Correlations {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", c.ID, c.Severity, c.Confidence, c.Score) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target to evaluate (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&fromStr, "from", "", "RFC3339 start time (default: 1 hour before --to)")
	cmd.Flags().StringVar(&toStr, "to", "", "RFC3339 end time (default: now)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report components without persisting any correlation")
	return cmd
}

func newCorrelationGraphCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph <id>",
		Short: "Show a correlation's graph — nodes, edges, confidence, and evidence references",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			nodes, err := svc.ListNodes(cmd.Context(), id)
			if err != nil {
				return err
			}
			edges, err := svc.ListEdges(cmd.Context(), id)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NODES")                                //nolint:errcheck
			fmt.Fprintln(w, "ID\tTYPE\tREFERENCE\tROLE\tTIMESTAMP") //nolint:errcheck
			for _, n := range nodes {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", n.ID, n.Type, n.ReferenceID, n.Role, n.Timestamp.Format(time.RFC3339)) //nolint:errcheck
			}
			fmt.Fprintln(w, "\nEDGES")                                                        //nolint:errcheck
			fmt.Fprintln(w, "SOURCE\tTARGET\tRELATIONSHIP\tPROVENANCE\tCONFIDENCE\tSTRATEGY") //nolint:errcheck
			for _, e := range edges {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.SourceNodeID, e.TargetNodeID, e.Relationship, e.Provenance, e.Confidence, e.StrategyID) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newCorrelationTimelineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "timeline <id>",
		Short: "Show a correlation's unified timeline, sorted by observation timestamp",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			nodes, err := svc.ListNodes(cmd.Context(), id)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tTYPE\tREFERENCE") //nolint:errcheck
			for _, n := range nodes {                     // already ordered by timestamp — see ListNodes
				fmt.Fprintf(w, "%s\t%s\t%s\n", n.Timestamp.Format(time.RFC3339), n.Type, n.ReferenceID) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newCorrelationEvidenceCommand() *cobra.Command {
	var sourceType string
	cmd := &cobra.Command{
		Use:   "evidence <id>",
		Short: "List a correlation's evidence (its graph nodes), optionally filtered by type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			nodes, err := svc.ListNodes(cmd.Context(), id)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tREFERENCE\tROLE\tOBSERVED AT") //nolint:errcheck
			for _, n := range nodes {
				if sourceType != "" && string(n.Type) != sourceType {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n.Type, n.ReferenceID, n.Role, n.Timestamp.Format(time.RFC3339)) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&sourceType, "type", "", "filter by node type: finding|detection_match|alert|asset|endpoint|intelligence_record")
	return cmd
}

func newCorrelationConfirmCommand() *cobra.Command {
	var actorID, notes string
	cmd := &cobra.Command{
		Use:   "confirm <id>",
		Short: "Confirm a correlation — an explicit analyst judgment, never automatic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			if actorID == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			c, err := svc.Confirm(cmd.Context(), id, actorID, notes)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Correlation %s is now %s.\n", c.ID, c.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&notes, "notes", "", "optional confirmation notes")
	return cmd
}

func newCorrelationDismissCommand() *cobra.Command {
	var actorID, reason string
	cmd := &cobra.Command{
		Use:   "dismiss <id>",
		Short: "Dismiss a correlation — a reason is required",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			c, err := svc.Dismiss(cmd.Context(), id, actorID, reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Correlation %s is now %s.\n", c.ID, c.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier")
	cmd.Flags().StringVar(&reason, "reason", "", "why this correlation is being dismissed (required)")
	return cmd
}

func newCorrelationMergeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "merge <survivor-id> <source-id...>",
		Short: "Merge one or more correlations into a survivor — original ids and evidence are preserved",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			survivorID, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid survivor id: %w", err)
			}
			sourceIDs := make([]uuid.UUID, 0, len(args)-1)
			for _, arg := range args[1:] {
				id, err := uuid.Parse(arg)
				if err != nil {
					return fmt.Errorf("invalid source id %q: %w", arg, err)
				}
				sourceIDs = append(sourceIDs, id)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			result, err := svc.Merge(cmd.Context(), survivorID, sourceIDs)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Merged %d correlation(s) into %s.\n", len(sourceIDs), result.ID) //nolint:errcheck
			return nil
		},
	}
	return cmd
}

func newCorrelationSplitCommand() *cobra.Command {
	var title, actorID string
	var nodeIDStrs []string
	cmd := &cobra.Command{
		Use:   "split <id>",
		Short: "Split evidence nodes out of a correlation into a brand-new one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			if len(nodeIDStrs) == 0 {
				return fmt.Errorf("--node is required (repeatable)")
			}
			nodeIDs := make([]uuid.UUID, 0, len(nodeIDStrs))
			for _, s := range nodeIDStrs {
				nid, err := uuid.Parse(s)
				if err != nil {
					return fmt.Errorf("invalid --node %q: %w", s, err)
				}
				nodeIDs = append(nodeIDs, nid)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			result, err := svc.Split(cmd.Context(), id, nodeIDs, title, actorID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created correlation %s, split from %s.\n", result.ID, id) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&nodeIDStrs, "node", nil, "a correlation-node id to move to the new correlation (repeatable, required)")
	cmd.Flags().StringVar(&title, "title", "", "title for the new correlation")
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier")
	return cmd
}

func newCorrelationInvestigateCommand() *cobra.Command {
	var actorID string
	cmd := &cobra.Command{
		Use:   "investigate <id>",
		Short: "Attach a correlation to a new investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			if actorID == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			inv, err := svc.AttachToInvestigation(cmd.Context(), id, actorID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created investigation %s (%s).\n", inv.ID, inv.Title) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier (required)")
	return cmd
}

func newCorrelationExportCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a correlation's full graph/evidence/timeline/explanation as JSON or YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			svc, db, err := buildCorrelationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			export, err := svc.ExportCorrelation(cmd.Context(), id)
			if err != nil {
				return err
			}
			var out []byte
			if strings.ToLower(format) == "yaml" {
				out, err = correlationsvc.EncodeYAML(export)
			} else {
				out, err = correlationsvc.EncodeJSON(export)
			}
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "json|yaml")
	return cmd
}
