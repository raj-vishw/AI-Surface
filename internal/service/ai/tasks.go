package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/ai"
	domainai "ai-recon-platform/internal/domain/ai"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	apperrors "ai-recon-platform/internal/errors"
)

// TaskRequest is one caller's ask — enough to build a Context, run
// Assistant, and persist the full audit trail.
type TaskRequest struct {
	TargetID        uuid.UUID
	InvestigationID *uuid.UUID
	SessionID       *uuid.UUID
	UserID          string
	Provider        string // empty uses Config.DefaultProvider
	Instructions    string // analyst's own free-form ask; empty for a fixed task
}

func toDomainTaskType(t ai.TaskType) domainai.TaskType       { return domainai.TaskType(t) }
func toDomainConfidence(c ai.Confidence) domainai.Confidence { return domainai.Confidence(c) }

// runTask is the single choke point every AI task in this package goes
// through: rate limiting, timeout enforcement, provider resolution,
// Assistant.Run, and the full Request/Response/timeline audit trail
// (phase13.md §52/§53/§55/§56). No task function below duplicates any of
// this.
func (s *Service) runTask(ctx context.Context, req TaskRequest, task ai.TaskType, evidence ai.Context, build func(ai.Context) ai.StructuredResult) (ai.Result, error) {
	if req.UserID == "" {
		return ai.Result{}, apperrors.NewValidation("user_id is required", nil)
	}
	if !s.limiter.Allow(req.UserID, req.TargetID.String()) {
		return ai.Result{}, apperrors.NewUnavailable("AI request rate limit exceeded for this user or target — try again shortly", nil)
	}
	defer s.limiter.Release()

	provider, err := s.provider(req.Provider)
	if err != nil {
		return ai.Result{}, apperrors.NewUnavailable("no usable AI provider is configured", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	result, err := s.assistant.Run(runCtx, provider, task, evidence, req.Instructions, build)
	if err != nil {
		return ai.Result{}, apperrors.NewUnavailable("AI provider request failed", err)
	}

	s.persistTaskAudit(ctx, req, result)
	return result, nil
}

// persistTaskAudit writes the Request/Response audit rows and, when
// investigation-scoped, a timeline event — logged-and-continued on
// failure so an audit-write problem never hides an already-produced,
// already-validated AI result from the caller (phase13.md §53).
func (s *Service) persistTaskAudit(ctx context.Context, req TaskRequest, result ai.Result) {
	domainReq := domainai.Request{
		TargetID: req.TargetID, SessionID: req.SessionID, InvestigationID: req.InvestigationID,
		UserID: req.UserID, TaskType: toDomainTaskType(result.TaskType),
		Instructions: req.Instructions, PromptVersion: result.PromptVersion, ContextHash: result.ContextHash,
	}
	savedReq, err := s.requests.CreateRequest(ctx, domainReq)
	if err != nil {
		s.logger.Error("ai_request_audit_failed", "task", result.TaskType, "error", err)
		return
	}

	domainResp := domainai.Response{
		RequestID: savedReq.ID, Content: result.Content, Model: result.Model, Provider: result.Provider,
		PromptVersion: result.PromptVersion, Confidence: toDomainConfidence(result.Confidence),
		Citations: result.Citations, ResponseHash: result.ResponseHash,
		InputTokens: result.InputTokens, OutputTokens: result.OutputTokens, LatencyMS: result.Latency.Milliseconds(),
	}
	if _, err := s.responses.CreateResponse(ctx, domainResp); err != nil {
		s.logger.Error("ai_response_audit_failed", "task", result.TaskType, "error", err)
	}

	if req.InvestigationID != nil {
		event := domaininvestigation.TimelineEvent{
			TargetID: req.TargetID, InvestigationID: *req.InvestigationID, Timestamp: time.Now(),
			Type: domaininvestigation.EventAIAnalysisGenerated, SourceType: domaininvestigation.EntityInvestigation,
			SourceID: req.InvestigationID, Title: fmt.Sprintf("AI %s generated", result.TaskType), Actor: "ai:" + result.Provider,
		}
		if _, err := s.timeline.AppendEvent(ctx, event); err != nil {
			s.logger.Error("ai_timeline_audit_failed", "task", result.TaskType, "error", err)
		}
	}
}

// SummarizeInvestigation implements phase13.md §19.
func (s *Service) SummarizeInvestigation(ctx context.Context, req TaskRequest) (ai.Result, error) {
	evidence, err := s.BuildInvestigationContext(ctx, *req.InvestigationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskInvestigationSummary, evidence, ai.SummarizeInvestigation)
}

// GenerateInvestigationReport implements phase13.md §46.
func (s *Service) GenerateInvestigationReport(ctx context.Context, req TaskRequest) (ai.Result, error) {
	evidence, err := s.BuildInvestigationContext(ctx, *req.InvestigationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskReportDraft, evidence, ai.GenerateInvestigationReport)
}

// IdentifyEvidenceGaps implements phase13.md §25.
func (s *Service) IdentifyEvidenceGaps(ctx context.Context, req TaskRequest) (ai.Result, error) {
	evidence, err := s.BuildInvestigationContext(ctx, *req.InvestigationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskEvidenceGapAnalysis, evidence, ai.IdentifyEvidenceGaps)
}

// GenerateInvestigationQuestions implements phase13.md §26.
func (s *Service) GenerateInvestigationQuestions(ctx context.Context, req TaskRequest) (ai.Result, error) {
	evidence, err := s.BuildInvestigationContext(ctx, *req.InvestigationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskInvestigationQuestions, evidence, ai.GenerateInvestigationQuestionsResult)
}

// AnalyzeTimeline implements phase13.md §24, against either an
// investigation's own timeline or a target's general evidence.
func (s *Service) AnalyzeTimeline(ctx context.Context, req TaskRequest) (ai.Result, error) {
	var (
		evidence ai.Context
		err      error
	)
	if req.InvestigationID != nil {
		evidence, err = s.BuildInvestigationContext(ctx, *req.InvestigationID)
	} else {
		evidence, err = s.BuildTargetContext(ctx, req.TargetID)
	}
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskTimelineSummary, evidence, ai.AnalyzeTimeline)
}

// ExplainAlert implements phase13.md §20.
func (s *Service) ExplainAlert(ctx context.Context, req TaskRequest, alertID uuid.UUID) (ai.Result, error) {
	evidence, err := s.BuildAlertContext(ctx, alertID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskAlertExplanation, evidence, ai.ExplainAlert)
}

// ExplainDetection implements phase13.md §21.
func (s *Service) ExplainDetection(ctx context.Context, req TaskRequest, matchID uuid.UUID) (ai.Result, error) {
	evidence, err := s.BuildDetectionContext(ctx, matchID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskDetectionExplanation, evidence, ai.ExplainDetection)
}

// AnalyzeCorrelation implements phase13.md §22.
func (s *Service) AnalyzeCorrelation(ctx context.Context, req TaskRequest, correlationID uuid.UUID) (ai.Result, error) {
	evidence, err := s.BuildCorrelationContext(ctx, correlationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskCorrelationAnalysis, evidence, ai.AnalyzeCorrelation)
}

// AnalyzeAttackChain implements phase13.md §23 — reuses the same
// correlation-scoped context an attack chain's stages are part of.
func (s *Service) AnalyzeAttackChain(ctx context.Context, req TaskRequest, correlationID uuid.UUID) (ai.Result, error) {
	evidence, err := s.BuildCorrelationContext(ctx, correlationID)
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskAttackChainAnalysis, evidence, ai.AnalyzeAttackChain)
}

// SummarizeIntelligence implements the general "summarize threat
// intelligence" requirement, against a target's own intelligence records.
func (s *Service) SummarizeIntelligence(ctx context.Context, req TaskRequest) (ai.Result, error) {
	if req.TargetID == uuid.Nil {
		return ai.Result{}, apperrors.NewValidation("target_id is required", nil)
	}
	evidence, err := s.BuildTargetContext(ctx, req.TargetID)
	if err != nil {
		return ai.Result{}, err
	}
	return s.runTask(ctx, req, ai.TaskIntelligenceSummary, evidence, ai.SummarizeIntelligence)
}

// ChatReply implements phase13.md §48/§49 — a follow-up question within
// an existing session, answered against that session's own bounded
// context (investigation-scoped if the session is, target-scoped
// otherwise).
func (s *Service) ChatReply(ctx context.Context, req TaskRequest, question string) (ai.Result, error) {
	var (
		evidence ai.Context
		err      error
	)
	if req.InvestigationID != nil {
		evidence, err = s.BuildInvestigationContext(ctx, *req.InvestigationID)
	} else {
		if req.TargetID == uuid.Nil {
			return ai.Result{}, apperrors.NewValidation("target_id is required when no investigation is scoped", nil)
		}
		evidence, err = s.BuildTargetContext(ctx, req.TargetID)
	}
	if err != nil {
		return ai.Result{}, err
	}
	if err := resolveOrCheckTarget(&req, evidence.TargetID); err != nil {
		return ai.Result{}, err
	}
	req.Instructions = question
	return s.runTask(ctx, req, ai.TaskChatReply, evidence, ai.SummarizeInvestigation)
}
