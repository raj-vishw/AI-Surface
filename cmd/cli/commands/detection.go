package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-recon-platform/internal/database"
	domainrule "ai-recon-platform/internal/domain/rule"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/logging"
	"ai-recon-platform/internal/repository/pagination"
	rulerepo "ai-recon-platform/internal/repository/rule"
	"ai-recon-platform/internal/ruleengine"
	"ai-recon-platform/internal/ruleengine/builtin"
	assetsvc "ai-recon-platform/internal/service/asset"
	rulesvc "ai-recon-platform/internal/service/rule"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewDetectionCommand returns the `ai-recon detection` command group —
// Phase 11's detection rule engine entry point. Rules are deterministic,
// versioned, and testable; this platform implements no autonomous
// response and no offensive action of any kind (phase11.md §127/§128).
func NewDetectionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detection",
		Short: "Define, version, test, and evaluate detection rules",
	}
	cmd.AddCommand(newDetectionListCommand())
	cmd.AddCommand(newDetectionShowCommand())
	cmd.AddCommand(newDetectionCreateCommand())
	cmd.AddCommand(newDetectionEditCommand())
	cmd.AddCommand(newDetectionEnableCommand())
	cmd.AddCommand(newDetectionDisableCommand())
	cmd.AddCommand(newDetectionVersionsCommand())
	cmd.AddCommand(newDetectionExportCommand())
	cmd.AddCommand(newDetectionImportCommand())
	cmd.AddCommand(newDetectionEvaluateCommand())
	cmd.AddCommand(newDetectionBuiltinCommand())
	cmd.AddCommand(newDetectionSuppressCommand())
	return cmd
}

// buildRuleService wires a *rulesvc.Service against a fresh database
// connection. Callers must close the returned *database.Pool.
func buildRuleService(cmd *cobra.Command) (*rulesvc.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if !cfg.DetectionRules.Enabled {
		return nil, nil, fmt.Errorf("detection_rules.enabled is false in the effective configuration")
	}

	logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
	ctx := cmd.Context()
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	engineCfg := ruleengine.Config{
		MaxConcurrency: cfg.DetectionRules.Evaluation.MaxConcurrency, EvaluationTimeout: cfg.DetectionRules.Evaluation.Timeout,
		ClockSkew: cfg.DetectionRules.Evaluation.ClockSkew, SuppressionWindow: cfg.DetectionRules.SuppressionDefaultWindow,
		HistoricalMaxRange: cfg.DetectionRules.Historical.MaxRange,
	}

	targets := targetsvc.NewService(db)
	assets := assetsvc.NewService(db)
	svc := rulesvc.NewService(db, targets, assets, engineCfg, logger)
	return svc, db, nil
}

func resolveRuleTargetType(raw string) domaintarget.Type {
	t := domaintarget.Type(strings.ToUpper(raw))
	if t == "" {
		return domaintarget.TypeDomain
	}
	return t
}

// loadDefinitionFile reads a rule Definition from a JSON or YAML file,
// selecting the parser by file extension.
func loadDefinitionFile(path string) (ruleengine.Definition, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied CLI argument, not external/user input
	if err != nil {
		return ruleengine.Definition{}, fmt.Errorf("reading definition file: %w", err)
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		return ruleengine.ParseYAML(data)
	}
	return ruleengine.ParseJSON(data)
}

func newDetectionListCommand() *cobra.Command {
	var targetValue, targetType, status string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detection rules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			filter := rulerepo.ListFilter{Status: domainrule.Status(status), Pagination: pagination.Params{Limit: pagination.MaxLimit}}
			if targetValue != "" {
				target, err := svc.ResolveTarget(cmd.Context(), resolveRuleTargetType(targetType), targetValue)
				if err != nil {
					return err
				}
				filter.TargetID = target.ID
			}
			page, err := svc.ListRules(cmd.Context(), filter)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSTATUS\tTYPE\tSEVERITY\tCONFIDENCE") //nolint:errcheck
			for _, r := range page.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Status, r.RuleType, r.Severity, r.Confidence) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "filter by target")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&status, "status", "", "draft|enabled|disabled|deprecated")
	return cmd
}

func newDetectionShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <rule-id>",
		Short: "Show one detection rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			r, err := svc.GetRule(cmd.Context(), id)
			if err != nil {
				return err
			}
			versions, err := svc.ListVersions(cmd.Context(), id)
			if err != nil {
				return err
			}
			var version domainrule.Version
			if len(versions) > 0 {
				version = versions[len(versions)-1]
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Name:\t%s\n", r.Name)                     //nolint:errcheck
			fmt.Fprintf(w, "Status:\t%s\n", r.Status)                 //nolint:errcheck
			fmt.Fprintf(w, "Type:\t%s\n", r.RuleType)                 //nolint:errcheck
			fmt.Fprintf(w, "Severity:\t%s\n", r.Severity)             //nolint:errcheck
			fmt.Fprintf(w, "Confidence:\t%s\n", r.Confidence)         //nolint:errcheck
			fmt.Fprintf(w, "Category:\t%s\n", r.Category)             //nolint:errcheck
			fmt.Fprintf(w, "Tags:\t%s\n", strings.Join(r.Tags, ", ")) //nolint:errcheck
			fmt.Fprintf(w, "Latest Version:\t%d\n", version.Version)  //nolint:errcheck
			fmt.Fprintf(w, "Created By:\t%s\n", r.CreatedBy)          //nolint:errcheck
			return w.Flush()
		},
	}
	return cmd
}

func newDetectionCreateCommand() *cobra.Command {
	var targetValue, targetType, name, description, category, definitionFile, createdBy string
	var tags []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new detection rule (status: draft) from a JSON/YAML definition file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if targetValue == "" || name == "" || definitionFile == "" || createdBy == "" {
				return fmt.Errorf("--target, --name, --definition-file, and --created-by are all required")
			}
			def, err := loadDefinitionFile(definitionFile)
			if err != nil {
				return err
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			r, version, err := svc.CreateRule(cmd.Context(), rulesvc.CreateInput{
				TargetType: resolveRuleTargetType(targetType), TargetValue: targetValue,
				Name: name, Description: description, Category: category, Tags: tags,
				Definition: def, ChangeDescription: "initial version", CreatedBy: createdBy,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created rule %s (%s), version %d.\n", r.Name, r.ID, version.Version) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target this rule belongs to (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&name, "name", "", "stable rule name (required)")
	cmd.Flags().StringVar(&description, "description", "", "rule description")
	cmd.Flags().StringVar(&category, "category", "", "rule category")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "comma-separated tags")
	cmd.Flags().StringVar(&definitionFile, "definition-file", "", "path to a JSON/YAML rule definition (required)")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	return cmd
}

func newDetectionEditCommand() *cobra.Command {
	var definitionFile, changeDescription, createdBy string
	cmd := &cobra.Command{
		Use:   "edit <rule-id>",
		Short: "Create a new version of a rule from a JSON/YAML definition file (never mutates a prior version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			if definitionFile == "" || createdBy == "" {
				return fmt.Errorf("--definition-file and --created-by are required")
			}
			def, err := loadDefinitionFile(definitionFile)
			if err != nil {
				return err
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			version, err := svc.CreateVersion(cmd.Context(), id, def, changeDescription, createdBy)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created version %d.\n", version.Version) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&definitionFile, "definition-file", "", "path to a JSON/YAML rule definition (required)")
	cmd.Flags().StringVar(&changeDescription, "change-description", "", "what changed in this version")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	return cmd
}

func newDetectionEnableCommand() *cobra.Command {
	var actorID string
	cmd := &cobra.Command{
		Use:   "enable <rule-id>",
		Short: "Enable a rule — it will produce new matches on future evaluation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			r, err := svc.Enable(cmd.Context(), id, actorID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Rule %s is now %s.\n", r.Name, r.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier")
	return cmd
}

func newDetectionDisableCommand() *cobra.Command {
	var actorID string
	cmd := &cobra.Command{
		Use:   "disable <rule-id>",
		Short: "Disable a rule — no new matches are produced; history remains available",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			r, err := svc.Disable(cmd.Context(), id, actorID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Rule %s is now %s.\n", r.Name, r.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier")
	return cmd
}

func newDetectionVersionsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "versions <rule-id>",
		Short: "List every version of a rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			versions, err := svc.ListVersions(cmd.Context(), id)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "VERSION\tENABLED\tCREATED BY\tCREATED AT\tCHANGE") //nolint:errcheck
			for _, v := range versions {
				fmt.Fprintf(w, "%d\t%t\t%s\t%s\t%s\n", v.Version, v.Enabled, v.CreatedBy, //nolint:errcheck
					v.CreatedAt.Format(time.RFC3339), v.ChangeDescription)
			}
			return w.Flush()
		},
	}
	return cmd
}

func newDetectionExportCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export <rule-id>",
		Short: "Export a rule's latest version as JSON or YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			_, def, err := svc.Export(cmd.Context(), id)
			if err != nil {
				return err
			}
			var out []byte
			if strings.ToLower(format) == "yaml" {
				out, err = ruleengine.EncodeYAML(def)
			} else {
				out, err = ruleengine.EncodeJSON(def)
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

func newDetectionImportCommand() *cobra.Command {
	var targetValue, targetType, name, createdBy string
	var enable bool
	cmd := &cobra.Command{
		Use:   "import <definition-file>",
		Short: "Import a rule definition from a JSON/YAML file — validated before persistence, never executed during import",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetValue == "" || name == "" || createdBy == "" {
				return fmt.Errorf("--target, --name, and --created-by are all required")
			}
			def, err := loadDefinitionFile(args[0])
			if err != nil {
				return err
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			r, version, err := svc.Import(cmd.Context(), rulesvc.ImportInput{
				TargetType: resolveRuleTargetType(targetType), TargetValue: targetValue,
				Rule: rulesvc.ExportedRule{Name: name}, Definition: def, CreatedBy: createdBy, Enable: enable,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Imported rule %s (%s), version %d, status %s.\n", r.Name, r.ID, version.Version, r.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target this rule belongs to (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&name, "name", "", "stable rule name (required)")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	cmd.Flags().BoolVar(&enable, "enable", false, "enable the rule immediately (default: draft)")
	return cmd
}

func newDetectionEvaluateCommand() *cobra.Command {
	var fromStr, toStr string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "evaluate <rule-id>",
		Short: "Evaluate a rule against events observed within [--from, --to)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid rule id: %w", err)
			}
			to := time.Now().UTC()
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

			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			result, err := svc.Evaluate(cmd.Context(), id, from, to, dryRun)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Rule:\t%s (version %d)\n", result.Rule.Name, result.Version.Version) //nolint:errcheck
			fmt.Fprintf(w, "Dry Run:\t%t\n", result.DryRun)                                      //nolint:errcheck
			fmt.Fprintf(w, "Events Considered:\t%d\n", result.EventsConsidered)                  //nolint:errcheck
			fmt.Fprintf(w, "Matches:\t%d\n", len(result.Matches))                                //nolint:errcheck
			fmt.Fprintf(w, "Alerts:\t%d\n", len(result.Alerts))                                  //nolint:errcheck
			fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)                                   //nolint:errcheck
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&fromStr, "from", "", "RFC3339 start time (default: 1 hour before --to)")
	cmd.Flags().StringVar(&toStr, "to", "", "RFC3339 end time (default: now)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report matches without creating any alert or persistent match")
	return cmd
}

func newDetectionSuppressCommand() *cobra.Command {
	var scope, reason, actorID string
	var durationStr string
	cmd := &cobra.Command{
		Use:   "suppress <scope-id>",
		Short: "Suppress future matches/alerts for a rule, match, or alert (reason required; evidence is never deleted)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid id: %w", err)
			}
			if reason == "" || actorID == "" {
				return fmt.Errorf("--reason and --actor are required")
			}
			var duration time.Duration
			if durationStr != "" {
				duration, err = time.ParseDuration(durationStr)
				if err != nil {
					return fmt.Errorf("invalid --duration: %w", err)
				}
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			sup, err := svc.Suppress(cmd.Context(), domainrule.SuppressionScope(scope), id, reason, actorID, duration)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Suppression %s created for %s %s.\n", sup.ID, sup.Scope, sup.ScopeID) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "rule", "rule|match|alert")
	cmd.Flags().StringVar(&reason, "reason", "", "why this is being suppressed (required)")
	cmd.Flags().StringVar(&actorID, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&durationStr, "duration", "", "e.g. 30m — omit for indefinite")
	return cmd
}

func newDetectionBuiltinCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "builtin",
		Short: "Inspect, test, and install this platform's built-in detection rules",
	}
	cmd.AddCommand(newDetectionBuiltinListCommand())
	cmd.AddCommand(newDetectionBuiltinTestCommand())
	cmd.AddCommand(newDetectionBuiltinInstallCommand())
	return cmd
}

func findBuiltin(name string) (builtin.Rule, bool) {
	for _, r := range builtin.All() {
		if r.Name == name {
			return r, true
		}
	}
	return builtin.Rule{}, false
}

func newDetectionBuiltinListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every built-in detection rule",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tSEVERITY\tDESCRIPTION") //nolint:errcheck
			for _, r := range builtin.All() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.Definition.RuleType, r.Definition.Severity, r.Description) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newDetectionBuiltinTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Run a built-in rule's own positive/negative/boundary test suite (phase11.md §49's dry-run test workflow)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, ok := findBuiltin(args[0])
			if !ok {
				return fmt.Errorf("no built-in rule named %q", args[0])
			}
			report, err := ruleengine.RunTest(r.Definition, r.Tests)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Rule:\t%s\n", r.Name) //nolint:errcheck
			status := "PASS"
			if !report.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(w, "Result:\t%s\n\n", status) //nolint:errcheck
			for _, res := range report.Results {
				caseStatus := "PASS"
				if !res.Passed {
					caseStatus = "FAIL: " + res.Reason
				}
				fmt.Fprintf(w, "%s\t%s\n", res.Name, caseStatus) //nolint:errcheck
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if !report.Passed {
				return fmt.Errorf("one or more test cases failed")
			}
			return nil
		},
	}
	return cmd
}

func newDetectionBuiltinInstallCommand() *cobra.Command {
	var targetValue, targetType, createdBy string
	var enable bool
	cmd := &cobra.Command{
		Use:   "install <name>",
		Short: "Persist a built-in rule for a target (status: draft unless --enable)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, ok := findBuiltin(args[0])
			if !ok {
				return fmt.Errorf("no built-in rule named %q", args[0])
			}
			if targetValue == "" || createdBy == "" {
				return fmt.Errorf("--target and --created-by are required")
			}
			svc, db, err := buildRuleService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			r, version, err := svc.Import(cmd.Context(), rulesvc.ImportInput{
				TargetType: resolveRuleTargetType(targetType), TargetValue: targetValue,
				Rule: rulesvc.ExportedRule{
					Name: b.Name, Description: b.Description, Category: b.Category, Tags: b.Tags,
				},
				Definition: b.Definition, CreatedBy: createdBy, Enable: enable,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed %s (%s), version %d, status %s.\n", r.Name, r.ID, version.Version, r.Status) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target this rule belongs to (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "analyst identifier (required)")
	cmd.Flags().BoolVar(&enable, "enable", false, "enable the rule immediately (default: draft)")
	return cmd
}
