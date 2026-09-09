package ai

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"ai-surface-platform/internal/ai"
	domainai "ai-surface-platform/internal/domain/ai"
	domainintel "ai-surface-platform/internal/domain/intelligence"
	apperrors "ai-surface-platform/internal/errors"
	assetrepo "ai-surface-platform/internal/repository/asset"
	findingrepo "ai-surface-platform/internal/repository/finding"
	intelrepo "ai-surface-platform/internal/repository/intelligence"
	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// dataSource implements ai.DataSource against Service's real
// repositories — the only place in this package where a tool call ever
// touches the database, mirroring internal/service/correlation.
// observations.go's identical "the service layer, not the engine, talks
// to repositories" boundary. Every method enforces TargetID scoping
// before returning anything (phase13.md §30/§61) — this platform's
// authorization boundary, since no per-resource RBAC exists.
type dataSource struct{ svc *Service }

func parseUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, apperrors.NewValidation(fmt.Sprintf("invalid id %q", s), err)
	}
	return id, nil
}

func deniedCrossTarget() error {
	return apperrors.NewForbidden("the requested resource does not belong to this session's target", nil)
}

func (d dataSource) GetInvestigation(ctx context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	invID, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	inv, err := d.svc.investigations.GetByID(ctx, invID)
	if err != nil {
		return nil, err
	}
	if inv.TargetID.String() != scope.TargetID {
		return nil, deniedCrossTarget()
	}
	return []ai.Fact{investigationToFact(inv)}, nil
}

func (d dataSource) GetAlert(ctx context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	alertID, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	a, err := d.svc.alerts.GetAlertByID(ctx, alertID)
	if err != nil {
		return nil, err
	}
	if a.TargetID.String() != scope.TargetID {
		return nil, deniedCrossTarget()
	}
	return []ai.Fact{alertToFact(a)}, nil
}

func (d dataSource) GetDetection(ctx context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	matchID, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	m, err := d.svc.matches.GetMatchByID(ctx, matchID)
	if err != nil {
		return nil, err
	}
	if m.TargetID.String() != scope.TargetID {
		return nil, deniedCrossTarget()
	}
	ruleName := ""
	if r, err := d.svc.rules.GetRuleByID(ctx, m.RuleID); err == nil {
		ruleName = r.Name
	}
	return []ai.Fact{detectionToFact(m, ruleName)}, nil
}

func (d dataSource) GetCorrelation(ctx context.Context, scope ai.ToolScope, id string) ([]ai.Fact, error) {
	corrID, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	c, err := d.svc.correlations.GetCorrelationByID(ctx, corrID)
	if err != nil {
		return nil, err
	}
	if c.TargetID.String() != scope.TargetID {
		return nil, deniedCrossTarget()
	}

	facts := []ai.Fact{correlationToFact(c)}

	nodes, err := d.svc.nodes.ListNodes(ctx, corrID)
	if err == nil {
		for _, n := range nodes {
			facts = append(facts, correlationNodeToFact(n))
		}
	}
	edges, err := d.svc.edges.ListEdges(ctx, corrID)
	if err == nil {
		for _, e := range edges {
			facts = append(facts, correlationEdgeToFact(e))
		}
	}
	if chain, chainErr := d.svc.chains.GetChainByCorrelationID(ctx, corrID); chainErr == nil {
		facts = append(facts, attackChainToFact(chain))
		if stages, stageErr := d.svc.stages.ListStages(ctx, chain.ID); stageErr == nil {
			for _, s := range stages {
				facts = append(facts, attackStageToFact(s))
			}
		}
	}
	return facts, nil
}

func (d dataSource) GetTimeline(ctx context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	if scope.InvestigationID == "" {
		return nil, apperrors.NewValidation("this session is not scoped to an investigation — there is no timeline to retrieve", nil)
	}
	invID, err := parseUUID(scope.InvestigationID)
	if err != nil {
		return nil, err
	}
	page, err := d.svc.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{
		InvestigationID: invID, Pagination: pagination.Params{Limit: limit},
	})
	if err != nil {
		return nil, err
	}
	facts := make([]ai.Fact, 0, len(page.Items))
	for _, e := range page.Items {
		facts = append(facts, timelineEventToFact(e))
	}
	return facts, nil
}

func (d dataSource) GetFindings(ctx context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	targetID, err := parseUUID(scope.TargetID)
	if err != nil {
		return nil, err
	}
	page, err := d.svc.findings.List(ctx, findingrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: limit}})
	if err != nil {
		return nil, err
	}
	facts := make([]ai.Fact, 0, len(page.Items))
	for _, f := range page.Items {
		facts = append(facts, findingToFact(f))
	}
	return facts, nil
}

func (d dataSource) GetAssets(ctx context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	targetID, err := parseUUID(scope.TargetID)
	if err != nil {
		return nil, err
	}
	page, err := d.svc.assets.List(ctx, assetrepo.ListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: limit}})
	if err != nil {
		return nil, err
	}
	facts := make([]ai.Fact, 0, len(page.Items))
	for _, a := range page.Items {
		facts = append(facts, assetToFact(a))
	}
	return facts, nil
}

func (d dataSource) GetIntelligence(ctx context.Context, scope ai.ToolScope, limit int) ([]ai.Fact, error) {
	targetID, err := parseUUID(scope.TargetID)
	if err != nil {
		return nil, err
	}
	page, err := d.svc.intelRecords.ListRecords(ctx, intelrepo.RecordListFilter{TargetID: targetID, Pagination: pagination.Params{Limit: limit}})
	if err != nil {
		return nil, err
	}
	facts := make([]ai.Fact, 0, len(page.Items))
	for _, r := range page.Items {
		facts = append(facts, intelligenceToFact(r))
	}
	return facts, nil
}

// riskEntityTypesToTry is the fixed, documented lookup order GetRisk uses
// since a bare entity id doesn't itself say which kind of entity it is
// (phase13.md's get_risk tool takes only an id) — a best-effort heuristic,
// not a claim that risk scores exist for other entity kinds too.
var riskEntityTypesToTry = []string{"asset", "finding", "investigation"}

func (d dataSource) GetRisk(ctx context.Context, scope ai.ToolScope, entityID string) ([]ai.Fact, error) {
	id, err := parseUUID(entityID)
	if err != nil {
		return nil, err
	}
	for _, et := range riskEntityTypesToTry {
		score, err := d.svc.risk.GetLatestRiskScore(ctx, domainintel.EntityType(et), id)
		if err == nil {
			if score.TargetID.String() != scope.TargetID {
				return nil, deniedCrossTarget()
			}
			return []ai.Fact{riskToFact(score)}, nil
		}
	}
	return nil, apperrors.NewNotFound("no risk score found for this entity", nil)
}

// auditToolCall implements ai.AuditFunc against internal/repository/ai
// (phase13.md §34). Failures to write the audit row are logged but never
// surfaced back to the tool caller — an audit-logging failure must not
// itself block an already-completed, already-read-only tool call.
func (s *Service) auditToolCall(rec ai.ToolCallRecord) {
	targetID, err := uuid.Parse(rec.Scope.TargetID)
	if err != nil {
		return
	}
	userID := rec.Scope.UserID
	if userID == "" {
		userID = "unknown"
	}
	call := domainai.ToolCall{
		TargetID: targetID, UserID: userID, Tool: rec.Tool,
		Arguments: map[string]any(rec.Arguments), ResultStatus: domainai.ToolResultStatus(rec.Status),
		ResultSummary: rec.ResultSummary, Error: rec.Error,
	}
	if _, err := s.toolCalls.RecordToolCall(context.Background(), call); err != nil {
		s.logger.Error("ai_tool_call_audit_failed", "tool", rec.Tool, "error", err)
	}
}
