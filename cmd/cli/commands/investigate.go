package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-surface-platform/internal/database"
	domaininvestigation "ai-surface-platform/internal/domain/investigation"
	domaintarget "ai-surface-platform/internal/domain/target"
	"ai-surface-platform/internal/investigation"
	"ai-surface-platform/internal/investigation/correlation"
	"ai-surface-platform/internal/logging"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
	assetsvc "ai-surface-platform/internal/service/asset"
	investigationsvc "ai-surface-platform/internal/service/investigation"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewInvestigateCommand returns the `ai-surface investigate` command group
// — Phase 9's analyst case-management and correlation entry point. It
// reasons only over evidence Phase 2-8 already collected and persisted;
// it never performs a network request, an exploit, a credential attack,
// or an automatic remediation action of its own (phase9.md §88/§89).
func NewInvestigateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "investigate",
		Short: "Manage analyst investigations and run finding correlation",
	}
	cmd.AddCommand(newInvestigateCreateCommand())
	cmd.AddCommand(newInvestigateListCommand())
	cmd.AddCommand(newInvestigateShowCommand())
	cmd.AddCommand(newInvestigateTimelineCommand())
	cmd.AddCommand(newInvestigateCorrelateCommand())
	cmd.AddCommand(newInvestigateFindingsCommand())
	cmd.AddCommand(newInvestigateAttachCommand())
	cmd.AddCommand(newInvestigateNoteCommand())
	cmd.AddCommand(newInvestigateHypothesisCommand())
	cmd.AddCommand(newInvestigateCloseCommand())
	cmd.AddCommand(newInvestigateReopenCommand())
	cmd.AddCommand(newInvestigateExportCommand())
	cmd.AddCommand(newInvestigateClusterCommand())
	return cmd
}

// buildInvestigationService wires a *investigationsvc.Service against a
// fresh database connection, registering every built-in correlation rule
// (internal/investigation/correlation.RegisterAll). Callers must close
// the returned *database.Pool.
func buildInvestigationService(cmd *cobra.Command) (*investigationsvc.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if !cfg.Investigation.Enabled {
		return nil, nil, fmt.Errorf("investigation.enabled is false in the effective configuration")
	}

	logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
	ctx := cmd.Context()
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	registry := investigation.NewRegistry()
	if err := correlation.RegisterAll(registry); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("registering correlation rules: %w", err)
	}

	targets := targetsvc.NewService(db)
	assets := assetsvc.NewService(db)
	svc := investigationsvc.NewService(db, targets, assets, registry, logger)
	return svc, db, nil
}

func resolveTargetType(raw string) domaintarget.Type {
	t := domaintarget.Type(strings.ToUpper(raw))
	if t == "" {
		return domaintarget.TypeDomain
	}
	return t
}

func newInvestigateCreateCommand() *cobra.Command {
	var (
		targetValue, targetType, title, description, priority, severity string
		createdBy, assignedTo, findingIDStr, assetIDStr                 string
	)
	cmd := &cobra.Command{
		Use:   "create --target <target> --title <title> --created-by <analyst>",
		Short: "Open a new investigation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" || title == "" || createdBy == "" {
				return fmt.Errorf("--target, --title, and --created-by are all required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			input := investigationsvc.CreateInput{
				TargetType: resolveTargetType(targetType), TargetValue: targetValue,
				Title: title, Description: description, Priority: domaininvestigation.Priority(priority),
				Severity: domaininvestigation.Severity(severity), CreatedBy: createdBy, AssignedTo: assignedTo,
			}
			if findingIDStr != "" {
				id, err := uuid.Parse(findingIDStr)
				if err != nil {
					return fmt.Errorf("invalid --finding: %w", err)
				}
				input.FindingID = &id
			}
			if assetIDStr != "" {
				id, err := uuid.Parse(assetIDStr)
				if err != nil {
					return fmt.Errorf("invalid --asset: %w", err)
				}
				input.AssetID = &id
			}

			inv, err := svc.Create(cmd.Context(), input)
			if err != nil {
				return err
			}
			return printInvestigationTable(cmd, inv)
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target this investigation concerns (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&title, "title", "", "investigation title (required)")
	cmd.Flags().StringVar(&description, "description", "", "investigation description")
	cmd.Flags().StringVar(&priority, "priority", "", "low|normal|high|urgent")
	cmd.Flags().StringVar(&severity, "severity", "", "informational|low|medium|high|critical")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&assignedTo, "assigned-to", "", "analyst this investigation is assigned to")
	cmd.Flags().StringVar(&findingIDStr, "finding", "", "attach this finding (UUID) immediately on creation")
	cmd.Flags().StringVar(&assetIDStr, "asset", "", "attach this asset (UUID) immediately on creation")
	return cmd
}

func newInvestigateListCommand() *cobra.Command {
	var targetValue, targetType, status, severity, format string
	cmd := &cobra.Command{
		Use:   "list --target <target>",
		Short: "List investigations for a target",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" {
				return fmt.Errorf("--target is required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			targets := targetsvc.NewService(db)
			target, err := targets.GetByValue(cmd.Context(), resolveTargetType(targetType), targetValue)
			if err != nil {
				return fmt.Errorf("loading target: %w", err)
			}

			page, err := svc.List(cmd.Context(), investigationrepo.ListFilter{
				TargetID: target.ID, Status: domaininvestigation.Status(status), Severity: domaininvestigation.Severity(severity),
				Pagination: pagination.Params{Limit: pagination.MaxLimit},
			})
			if err != nil {
				return err
			}

			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(page.Items)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTITLE\tSTATUS\tSEVERITY\tPRIORITY\tASSIGNED TO") //nolint:errcheck
			for _, inv := range page.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", inv.ID, inv.Title, inv.Status, inv.Severity, inv.Priority, inv.AssignedTo) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target whose investigations to list (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&status, "status", "", "filter by status")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func printInvestigationTable(cmd *cobra.Command, inv domaininvestigation.Investigation) error {
	ew := &errWriter{w: cmd.OutOrStdout()}
	ew.printf("%s\n\n", inv.Title)
	ew.printf("ID:          %s\n", inv.ID)
	ew.printf("Status:      %s\n", inv.Status)
	ew.printf("Severity:    %s\n", inv.Severity)
	ew.printf("Confidence:  %s\n", inv.Confidence)
	ew.printf("Priority:    %s\n", inv.Priority)
	ew.printf("Assigned to: %s\n", inv.AssignedTo)
	ew.printf("Version:     %d\n", inv.Version)
	if inv.FirstObservedAt != nil {
		ew.printf("First observed: %s\n", inv.FirstObservedAt.Format(time.RFC3339))
	}
	if inv.LastObservedAt != nil {
		ew.printf("Last observed:  %s\n", inv.LastObservedAt.Format(time.RFC3339))
	}
	if inv.Description != "" {
		ew.printf("\n%s\n", inv.Description)
	}
	return ew.err
}

func newInvestigateShowCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "show <investigation-id>",
		Short: "Show an investigation's automatically generated summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			summary, err := svc.Summarize(cmd.Context(), id)
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(summary)
			}

			ew := &errWriter{w: cmd.OutOrStdout()}
			ew.printf("Investigation:\n    %s\n\n", summary.Title)
			ew.printf("Severity:\n    %s\n\nConfidence:\n    %s\n\n", summary.Severity, summary.Confidence)
			ew.printf("Assets:\n    %d\n\nEndpoints:\n    %d\n\nFindings:\n    %d (%d open)\n\n",
				summary.AssetCount, summary.EndpointCount, summary.FindingCount, summary.OpenFindingCount)
			ew.printf("Timeline:\n    %d events\n\nRelationships:\n    %d\n\nHypotheses:\n    %d\n\n",
				summary.EventCount, summary.RelationshipCount, summary.HypothesisCount)
			if summary.FirstObserved != nil {
				ew.printf("First observed:\n    %s\n", summary.FirstObserved.Format(time.RFC3339))
			}
			if summary.LastObserved != nil {
				ew.printf("Last observed:\n    %s\n", summary.LastObserved.Format(time.RFC3339))
			}
			return ew.err
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func newInvestigateTimelineCommand() *cobra.Command {
	var newestFirst bool
	var format string
	cmd := &cobra.Command{
		Use:   "timeline <investigation-id>",
		Short: "Show an investigation's chronological timeline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			page, err := svc.Timeline(cmd.Context(), id, newestFirst, pagination.Params{Limit: pagination.MaxLimit})
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(page.Items)
			}
			ew := &errWriter{w: cmd.OutOrStdout()}
			for _, e := range page.Items {
				ew.printf("%s\n    %s\n\n", e.Timestamp.Format(time.RFC3339), e.Title)
			}
			return ew.err
		},
	}
	cmd.Flags().BoolVar(&newestFirst, "newest-first", false, "show most recent events first")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func newInvestigateCorrelateCommand() *cobra.Command {
	var dryRun bool
	var format string
	cmd := &cobra.Command{
		Use:   "correlate <investigation-id>",
		Short: "Run finding correlation for an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			corrCfg := investigation.Config{
				Threshold: cfg.Investigation.Correlation.Threshold, TemporalWindow: cfg.Investigation.Correlation.TemporalWindow,
				Rules: cfg.Investigation.Correlation.Rules,
			}
			result, dryRunReport, err := svc.Correlate(cmd.Context(), id, corrCfg, dryRun)
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				ew := &errWriter{w: cmd.OutOrStdout()}
				ew.printf("Correlation Plan\n\nInvestigation:\n    %s\n\nFindings considered:\n    %d\n\nRules:\n    %s\n",
					dryRunReport.InvestigationID, dryRunReport.FindingsCount, strings.Join(dryRunReport.Rules, "\n    "))
				return ew.err
			}

			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			ew := &errWriter{w: cmd.OutOrStdout()}
			ew.printf("Correlation Results\n\nFindings used:\n    %d\n\nRelationships:\n", result.FindingsUsed)
			for _, rel := range result.Relationships {
				ew.printf("    [%s] %s (score %d, %s)\n        %s\n", rel.Status, rel.Type, rel.Score, rel.Confidence, rel.Explanation)
			}
			if len(result.RuleErrors) > 0 {
				ew.printf("\nRule errors (partial results — other rules still ran):\n")
				for _, e := range result.RuleErrors {
					ew.printf("    %s: %v\n", e.RuleID, e.Err)
				}
			}
			return ew.err
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report the correlation plan without creating any relationship")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func newInvestigateFindingsCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "findings <investigation-id>",
		Short: "List findings attached to an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			findings, err := svc.ListFindings(cmd.Context(), id)
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SEVERITY\tSTATUS\tTITLE") //nolint:errcheck
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Severity, f.Status, f.Title) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	return cmd
}

func newInvestigateAttachCommand() *cobra.Command {
	var findingIDStr, assetIDStr, endpointIDStr, relation, actor string
	cmd := &cobra.Command{
		Use:   "attach <investigation-id>",
		Short: "Attach a finding, asset, or endpoint to an investigation as evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			count := 0
			for _, v := range []string{findingIDStr, assetIDStr, endpointIDStr} {
				if v != "" {
					count++
				}
			}
			if count != 1 {
				return fmt.Errorf("exactly one of --finding, --asset, --endpoint is required")
			}

			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			ctx := cmd.Context()
			switch {
			case findingIDStr != "":
				fid, err := uuid.Parse(findingIDStr)
				if err != nil {
					return fmt.Errorf("invalid --finding: %w", err)
				}
				rel := domaininvestigation.RelationType(relation)
				if rel == "" {
					rel = domaininvestigation.RelationRelated
				}
				_, err = svc.AttachFinding(ctx, id, fid, rel, actor)
				return err
			case assetIDStr != "":
				aid, err := uuid.Parse(assetIDStr)
				if err != nil {
					return fmt.Errorf("invalid --asset: %w", err)
				}
				_, err = svc.AttachEvidence(ctx, id, domaininvestigation.EntityAsset, aid, actor)
				return err
			default:
				eid, err := uuid.Parse(endpointIDStr)
				if err != nil {
					return fmt.Errorf("invalid --endpoint: %w", err)
				}
				_, err = svc.AttachEvidence(ctx, id, domaininvestigation.EntityEndpoint, eid, actor)
				return err
			}
		},
	}
	cmd.Flags().StringVar(&findingIDStr, "finding", "", "finding id (UUID) to attach")
	cmd.Flags().StringVar(&assetIDStr, "asset", "", "asset id (UUID) to attach")
	cmd.Flags().StringVar(&endpointIDStr, "endpoint", "", "endpoint id (UUID) to attach")
	cmd.Flags().StringVar(&relation, "relation", "", "related|correlated|suspected|confirmed (findings only, default related)")
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	return cmd
}

func newInvestigateNoteCommand() *cobra.Command {
	var content, author string
	cmd := &cobra.Command{
		Use:   "note <investigation-id>",
		Short: "Add an immutable analyst note to an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if content == "" || author == "" {
				return fmt.Errorf("--content and --author are both required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			_, err = svc.AddNote(cmd.Context(), id, author, content)
			return err
		},
	}
	cmd.Flags().StringVar(&content, "content", "", "note content (required)")
	cmd.Flags().StringVar(&author, "author", "", "analyst identifier (required)")
	return cmd
}

func newInvestigateHypothesisCommand() *cobra.Command {
	var title, description, createdBy string
	cmd := &cobra.Command{
		Use:   "hypothesis <investigation-id>",
		Short: "Add an analyst hypothesis to an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if title == "" || createdBy == "" {
				return fmt.Errorf("--title and --created-by are both required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			h, err := svc.CreateHypothesis(cmd.Context(), id, title, description, createdBy)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Hypothesis created: %s (%s)\n", h.ID, h.Status)
			return err
		},
	}
	cmd.Flags().StringVar(&title, "title", "", "hypothesis title (required)")
	cmd.Flags().StringVar(&description, "description", "", "hypothesis description")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	return cmd
}

func newInvestigateCloseCommand() *cobra.Command {
	var actor, reason string
	cmd := &cobra.Command{
		Use:   "close <investigation-id>",
		Short: "Close an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			current, err := svc.GetByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			_, err = svc.Close(cmd.Context(), id, current.Version, actor, reason)
			return err
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier")
	cmd.Flags().StringVar(&reason, "reason", "", "why this investigation is being closed")
	return cmd
}

func newInvestigateReopenCommand() *cobra.Command {
	var actor, reason string
	cmd := &cobra.Command{
		Use:   "reopen <investigation-id>",
		Short: "Reopen a closed investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if reason == "" {
				return fmt.Errorf("--reason is required to reopen an investigation")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			current, err := svc.GetByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			_, err = svc.Reopen(cmd.Context(), id, current.Version, actor, reason)
			return err
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier")
	cmd.Flags().StringVar(&reason, "reason", "", "why this investigation is being reopened (required)")
	return cmd
}

func newInvestigateExportCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export <investigation-id>",
		Short: "Export an investigation as JSON, CSV, or Markdown",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			bundle, err := svc.BuildExportBundle(cmd.Context(), id)
			if err != nil {
				return err
			}
			data, err := investigationsvc.Export(bundle, investigationsvc.ExportFormat(format))
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "export format: json|csv|markdown")
	return cmd
}

func newInvestigateClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Manage system-suggested incident clusters",
	}
	cmd.AddCommand(newInvestigateClusterSuggestCommand())
	cmd.AddCommand(newInvestigateClusterListCommand())
	cmd.AddCommand(newInvestigateClusterAcceptCommand())
	cmd.AddCommand(newInvestigateClusterRejectCommand())
	return cmd
}

func newInvestigateClusterSuggestCommand() *cobra.Command {
	var targetValue, targetType string
	cmd := &cobra.Command{
		Use:   "suggest --target <target>",
		Short: "Suggest incident clusters from currently-open findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" {
				return fmt.Errorf("--target is required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			clusters, err := svc.SuggestClusters(cmd.Context(), resolveTargetType(targetType), targetValue)
			if err != nil {
				return err
			}
			ew := &errWriter{w: cmd.OutOrStdout()}
			if len(clusters) == 0 {
				ew.printf("(no clusters suggested)\n")
			}
			for _, c := range clusters {
				ew.printf("%s  %s  [%s]\n", c.ID, c.Title, c.Status)
			}
			return ew.err
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target to scan for cluster suggestions (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	return cmd
}

func newInvestigateClusterListCommand() *cobra.Command {
	var targetValue, targetType, status string
	cmd := &cobra.Command{
		Use:   "list --target <target>",
		Short: "List incident clusters for a target",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" {
				return fmt.Errorf("--target is required")
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			targets := targetsvc.NewService(db)
			target, err := targets.GetByValue(cmd.Context(), resolveTargetType(targetType), targetValue)
			if err != nil {
				return fmt.Errorf("loading target: %w", err)
			}
			page, err := svc.ListClusters(cmd.Context(), investigationrepo.ClusterListFilter{
				TargetID: target.ID, Status: domaininvestigation.ClusterStatus(status), Pagination: pagination.Params{Limit: pagination.MaxLimit},
			})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTITLE\tSTATUS\tCONFIDENCE") //nolint:errcheck
			for _, c := range page.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.ID, c.Title, c.Status, c.Confidence) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target whose clusters to list (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&status, "status", "", "filter by status: suggested|accepted|rejected")
	return cmd
}

func newInvestigateClusterAcceptCommand() *cobra.Command {
	var actor string
	cmd := &cobra.Command{
		Use:   "accept <cluster-id>",
		Short: "Accept a suggested cluster, converting it into an investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid cluster id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			inv, err := svc.AcceptCluster(cmd.Context(), id, actor)
			if err != nil {
				return err
			}
			return printInvestigationTable(cmd, inv)
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier")
	return cmd
}

func newInvestigateClusterRejectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reject <cluster-id>",
		Short: "Reject a suggested cluster (preserved, never deleted)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid cluster id: %w", err)
			}
			svc, db, err := buildInvestigationService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			_, err = svc.RejectCluster(cmd.Context(), id)
			return err
		},
	}
	return cmd
}
