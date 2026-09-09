package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	engineai "ai-surface-platform/internal/ai"
	"ai-surface-platform/internal/ai/providers/mock"
	"ai-surface-platform/internal/ai/providers/openai"
	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/logging"
	airepo "ai-surface-platform/internal/repository/ai"
	assetrepo "ai-surface-platform/internal/repository/asset"
	correlationrepo "ai-surface-platform/internal/repository/correlation"
	findingrepo "ai-surface-platform/internal/repository/finding"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
	rulerepo "ai-surface-platform/internal/repository/rule"
	aisvc "ai-surface-platform/internal/service/ai"
	targetsvc "ai-surface-platform/internal/service/target"
)

// NewAICommand returns the `ai-surface ai` command group — Phase 13's
// evidence-grounded investigation assistant. Every subcommand produces
// advisory output for an analyst to review; nothing here changes any
// alert/investigation/correlation/detection/risk state (phase13.md §90).
func NewAICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-assisted investigation copilot — advisory only, never autonomous",
	}
	cmd.AddCommand(newAIStatusCommand())
	cmd.AddCommand(newAISummarizeCommand())
	cmd.AddCommand(newAIAnalyzeCommand())
	cmd.AddCommand(newAIQuestionsCommand())
	cmd.AddCommand(newAIReportCommand())
	cmd.AddCommand(newAIExplainAlertCommand())
	cmd.AddCommand(newAIExplainDetectionCommand())
	cmd.AddCommand(newAIAnalyzeCorrelationCommand())
	cmd.AddCommand(newAISessionCommand())
	cmd.AddCommand(newAIChatCommand())
	cmd.AddCommand(newAINoteCommand())
	return cmd
}

// buildAIService wires a *aisvc.Service against a fresh database
// connection, registering every configured provider. Callers must close
// the returned *database.Pool.
func buildAIService(cmd *cobra.Command) (*aisvc.Service, *database.Pool, error) {
	cfg, err := loadConfig(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if !cfg.AI.Enabled {
		return nil, nil, fmt.Errorf("ai.enabled is false in the effective configuration")
	}

	logger := logging.New(logging.Options{Level: cfg.Logging.Level, Format: logging.Format(cfg.Logging.Format), Output: os.Stderr})
	ctx := cmd.Context()
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, nil, err
	}

	providers := engineai.NewProviderRegistry()
	if err := providers.Register(mock.New()); err != nil {
		db.Close()
		return nil, nil, err
	}
	if cfg.AI.Provider.Name == "openai" {
		if err := providers.Register(openai.New(openai.Config{
			Endpoint: cfg.AI.Provider.Endpoint, Model: cfg.AI.Provider.Model,
			APIKeyEnv: cfg.AI.Provider.APIKeyEnv, Timeout: cfg.AI.Timeouts.Request,
		})); err != nil {
			db.Close()
			return nil, nil, err
		}
	}

	targets := targetsvc.NewService(db)
	investigationRepo := investigationrepo.NewPostgresRepository(db)
	findingRepo := findingrepo.NewPostgresRepository(db)
	assetRepo := assetrepo.NewPostgresRepository(db)
	ruleRepo := rulerepo.NewPostgresRepository(db)
	correlationRepo := correlationrepo.NewPostgresRepository(db)
	intelRepo := intelrepo.NewPostgresRepository(db)
	aiRepo := airepo.NewPostgresRepository(db)

	svcCfg := aisvc.Config{
		RequestTimeout: cfg.AI.Timeouts.Request, ToolTimeout: cfg.AI.Timeouts.Tool,
		MaxRetries: cfg.AI.Retries.Max, RetryBackoff: cfg.AI.Retries.Backoff,
		Limits:          engineai.Limits{MaxFactsPerType: cfg.AI.Limits.MaxFactsPerType, MaxTotalFacts: cfg.AI.Limits.MaxTotalFacts},
		DefaultProvider: cfg.AI.Provider.Name,
		RateLimit: aisvc.RateLimitConfig{
			PerUserPerMinute: cfg.AI.RateLimit.PerUserPerMinute, PerTargetPerMinute: cfg.AI.RateLimit.PerTargetPerMinute,
			MaxConcurrent: cfg.AI.RateLimit.MaxConcurrent,
		},
	}

	svc := aisvc.NewService(
		db, targets,
		investigationRepo, investigationRepo, investigationRepo, investigationRepo,
		findingRepo, assetRepo,
		ruleRepo, ruleRepo, ruleRepo,
		correlationRepo, correlationRepo, correlationRepo, correlationRepo, correlationRepo,
		intelRepo, intelRepo,
		aiRepo, aiRepo, aiRepo, aiRepo, aiRepo,
		providers, svcCfg, logger,
	)
	return svc, db, nil
}

func printAIResult(cmd *cobra.Command, result engineai.Result) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Provider:\t%s (%s)\n", result.Provider, result.Model)                                                  //nolint:errcheck
	fmt.Fprintf(w, "AI Confidence:\t%s\n", result.Confidence)                                                              //nolint:errcheck
	fmt.Fprintf(w, "Truncated:\t%t\n", result.Truncated)                                                                   //nolint:errcheck
	fmt.Fprintln(w)                                                                                                        //nolint:errcheck
	_ = w.Flush()                                                                                                          //nolint:errcheck
	fmt.Fprintln(cmd.OutOrStdout(), result.Content)                                                                        //nolint:errcheck
	fmt.Fprintln(cmd.OutOrStdout(), "\n[AI-generated — advisory only, requires analyst review. Not a confirmed finding.]") //nolint:errcheck
}

func newAIStatusCommand() *cobra.Command {
	var provider string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether the AI subsystem is enabled and a provider is available",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			h := svc.CheckHealth(cmd.Context(), provider)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Enabled:\t%t\n", h.Enabled)     //nolint:errcheck
			fmt.Fprintf(w, "Provider:\t%s\n", h.Provider)   //nolint:errcheck
			fmt.Fprintf(w, "Available:\t%t\n", h.Available) //nolint:errcheck
			if h.Reason != "" {
				fmt.Fprintf(w, "Reason:\t%s\n", h.Reason) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "provider to check (defaults to the configured default)")
	return cmd
}

func newAISummarizeCommand() *cobra.Command {
	var actor, provider string
	cmd := &cobra.Command{
		Use:   "summarize <investigation-id>",
		Short: "Summarize an investigation: observations, timeline, gaps, next steps",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{InvestigationID: &id, UserID: actor, Provider: provider}
			result, err := svc.SummarizeInvestigation(cmd.Context(), req)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAIAnalyzeCommand() *cobra.Command {
	var actor, provider string
	cmd := &cobra.Command{
		Use:   "analyze <investigation-id>",
		Short: "Analyze an investigation's timeline: chronology, significant events, gaps",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{InvestigationID: &id, UserID: actor, Provider: provider}
			result, err := svc.AnalyzeTimeline(cmd.Context(), req)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAIQuestionsCommand() *cobra.Command {
	var actor, provider string
	cmd := &cobra.Command{
		Use:   "questions <investigation-id>",
		Short: "Generate evidence-gap-driven investigation questions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{InvestigationID: &id, UserID: actor, Provider: provider}
			result, err := svc.GenerateInvestigationQuestions(cmd.Context(), req)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAIReportCommand() *cobra.Command {
	var actor, provider string
	var saveAsNote bool
	cmd := &cobra.Command{
		Use:   "report <investigation-id>",
		Short: "Draft an investigation report — clearly marked AI-generated, requires analyst approval before use",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid investigation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{InvestigationID: &id, UserID: actor, Provider: provider}
			result, err := svc.GenerateInvestigationReport(cmd.Context(), req)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			if saveAsNote {
				note, err := svc.SaveNoteFromResponse(cmd.Context(), id, actor, result.Content)
				if err != nil {
					return fmt.Errorf("report generated, but saving as a draft note failed: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "\nSaved as draft note %s (AI-generated, pending analyst approval — see `ai-surface ai note approve`).\n", note.ID) //nolint:errcheck
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	cmd.Flags().BoolVar(&saveAsNote, "save-as-note", false, "save the draft report as an AI-generated investigation note")
	return cmd
}

func newAIExplainAlertCommand() *cobra.Command {
	var actor, provider string
	cmd := &cobra.Command{
		Use:   "explain-alert <alert-id>",
		Short: "Explain what triggered an alert, and why — never changes its severity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid alert id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{UserID: actor, Provider: provider}
			result, err := svc.ExplainAlert(cmd.Context(), req, id)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAIExplainDetectionCommand() *cobra.Command {
	var actor, provider string
	cmd := &cobra.Command{
		Use:   "explain-detection <detection-match-id>",
		Short: "Explain a detection match: rule, matched conditions, evidence, false-positive considerations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid detection match id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{UserID: actor, Provider: provider}
			result, err := svc.ExplainDetection(cmd.Context(), req, id)
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAIAnalyzeCorrelationCommand() *cobra.Command {
	var actor, provider string
	var chain bool
	cmd := &cobra.Command{
		Use:   "analyze-correlation <correlation-id>",
		Short: "Analyze a correlation's graph — or, with --chain, its attack chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid correlation id: %w", err)
			}
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			req := aisvc.TaskRequest{UserID: actor, Provider: provider}
			var result engineai.Result
			if chain {
				result, err = svc.AnalyzeAttackChain(cmd.Context(), req, id)
			} else {
				result, err = svc.AnalyzeCorrelation(cmd.Context(), req, id)
			}
			if err != nil {
				return err
			}
			printAIResult(cmd, result)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	cmd.Flags().BoolVar(&chain, "chain", false, "analyze the correlation's attack chain instead of its raw graph")
	return cmd
}

// --- session / chat / note --------------------------------------------------

func newAISessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage AI investigation sessions",
	}
	cmd.AddCommand(newAISessionNewCommand())
	cmd.AddCommand(newAISessionListCommand())
	cmd.AddCommand(newAISessionShowCommand())
	cmd.AddCommand(newAISessionClearCommand())
	cmd.AddCommand(newAISessionDeleteCommand())
	return cmd
}

func newAISessionNewCommand() *cobra.Command {
	var targetValue, targetType, investigationIDStr, actor string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Open a new AI session, optionally scoped to one investigation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if actor == "" {
				return fmt.Errorf("--actor is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			var targetID uuid.UUID
			var invID *uuid.UUID
			if investigationIDStr != "" {
				id, err := uuid.Parse(investigationIDStr)
				if err != nil {
					return fmt.Errorf("invalid --investigation: %w", err)
				}
				invID = &id
			}
			if targetValue != "" {
				target, err := svc.ResolveTarget(cmd.Context(), resolveCorrelationTargetType(targetType), targetValue)
				if err != nil {
					return err
				}
				targetID = target.ID
			} else if invID == nil {
				return fmt.Errorf("either --target or --investigation is required")
			}

			sess, err := svc.CreateSession(cmd.Context(), targetID, invID, actor)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s created.\n", sess.ID) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&targetValue, "target", "", "the target this session concerns (required unless --investigation is given)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "URL|HOST|DOMAIN — defaults to DOMAIN")
	cmd.Flags().StringVar(&investigationIDStr, "investigation", "", "scope this session to one investigation")
	cmd.Flags().StringVar(&actor, "actor", "", "analyst identifier (required)")
	return cmd
}

func newAISessionListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List AI sessions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			page, err := svc.ListSessions(cmd.Context(), airepo.SessionListFilter{Pagination: pagination.Params{Limit: pagination.MaxLimit}})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTARGET\tINVESTIGATION\tUSER\tUPDATED") //nolint:errcheck
			for _, sess := range page.Items {
				inv := ""
				if sess.InvestigationID != nil {
					inv = sess.InvestigationID.String()
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", sess.ID, sess.TargetID, inv, sess.UserID, sess.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newAISessionShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show a session and its message history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid session id: %w", err)
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			messages, err := svc.ListMessages(cmd.Context(), id, 0)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ROLE\tCONTENT") //nolint:errcheck
			for _, m := range messages {
				fmt.Fprintf(w, "%s\t%s\n", m.Role, m.Content) //nolint:errcheck
			}
			return w.Flush()
		},
	}
	return cmd
}

func newAISessionClearCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clear <session-id>",
		Short: "Clear a session's message history without deleting the session or any investigation data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid session id: %w", err)
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := svc.ClearSession(cmd.Context(), id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s message history cleared.\n", id) //nolint:errcheck
			return nil
		},
	}
	return cmd
}

func newAISessionDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <session-id>",
		Short: "Delete a session entirely",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid session id: %w", err)
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := svc.DeleteSession(cmd.Context(), id); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s deleted.\n", id) //nolint:errcheck
			return nil
		},
	}
	return cmd
}

func newAIChatCommand() *cobra.Command {
	var provider string
	cmd := &cobra.Command{
		Use:   "chat <session-id> <question>",
		Short: "Ask a follow-up question within an existing session",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid session id: %w", err)
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			reply, err := svc.Chat(cmd.Context(), id, args[1], provider)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), reply.Content)                                                //nolint:errcheck
			fmt.Fprintln(cmd.OutOrStdout(), "\n[AI-generated — advisory only, requires analyst review.]") //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "provider to use (defaults to the configured default)")
	return cmd
}

func newAINoteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "note",
		Short: "Manage AI-generated draft investigation notes",
	}
	cmd.AddCommand(newAINoteApproveCommand())
	return cmd
}

func newAINoteApproveCommand() *cobra.Command {
	var approver string
	cmd := &cobra.Command{
		Use:   "approve <note-id>",
		Short: "Approve an AI-generated draft note — an explicit, distinct analyst action, never automatic",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid note id: %w", err)
			}
			if approver == "" {
				return fmt.Errorf("--approver is required")
			}
			svc, db, err := buildAIService(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			note, err := svc.ApproveNote(cmd.Context(), id, approver)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Note %s approved by %s.\n", note.ID, approver) //nolint:errcheck
			return nil
		},
	}
	cmd.Flags().StringVar(&approver, "approver", "", "analyst identifier (required)")
	return cmd
}
