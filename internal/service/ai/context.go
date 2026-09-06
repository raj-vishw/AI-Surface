package ai

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/ai"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	apperrors "ai-recon-platform/internal/errors"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
)

// buildContext finalizes a raw fact slice into an ai.Context: bounds it
// (ai.Truncate), stamps GeneratedAt, and never includes a fact that
// wasn't already redacted by facts.go's own conversion functions
// (phase13.md §11/§12/§13).
func buildContext(targetID uuid.UUID, investigationID *uuid.UUID, facts []ai.Fact, limits ai.Limits) ai.Context {
	kept, truncated := ai.Truncate(facts, limits)
	c := ai.Context{TargetID: targetID.String(), Facts: kept, Truncated: truncated, GeneratedAt: time.Now()}
	if truncated {
		c.TruncationNote = ai.TruncationNote
	}
	if investigationID != nil {
		c.InvestigationID = investigationID.String()
	}
	return c
}

// BuildInvestigationContext gathers everything relevant to summarizing,
// reporting on, or answering questions about one investigation
// (phase13.md §10): the investigation itself, its attached evidence
// (findings/alerts/detections/correlations/assets, resolved by
// EvidenceRef.SourceType), its timeline, and its notes. Authorization is
// enforced by construction — every fact here traces back to rows already
// scoped to this investigation or explicitly attached to it; nothing
// outside that scope is ever fetched (phase13.md §61).
func (s *Service) BuildInvestigationContext(ctx context.Context, investigationID uuid.UUID) (ai.Context, error) {
	inv, err := s.investigations.GetByID(ctx, investigationID)
	if err != nil {
		return ai.Context{}, err
	}

	facts := []ai.Fact{investigationToFact(inv)}

	evidencePage, err := s.evidence.ListEvidence(ctx, investigationrepo.EvidenceListFilter{
		InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err == nil {
		for _, ev := range evidencePage.Items {
			if f, ok := s.resolveEvidenceFact(ctx, ev); ok {
				facts = append(facts, f)
			}
		}
	}

	timelinePage, err := s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{
		InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit},
	})
	if err == nil {
		for _, e := range timelinePage.Items {
			facts = append(facts, timelineEventToFact(e))
		}
	}

	if notes, err := s.notes.ListNotes(ctx, investigationID); err == nil {
		for _, n := range notes {
			facts = append(facts, noteToFact(n))
		}
	}

	return buildContext(inv.TargetID, &investigationID, facts, s.cfg.Limits), nil
}

// resolveEvidenceFact turns one EvidenceRef into a Fact by resolving the
// underlying row it references — a reference, never a copy, exactly
// mirroring EvidenceRef's own doc comment ("the investigation's evidence
// list reflects that change automatically on the next read").
func (s *Service) resolveEvidenceFact(ctx context.Context, ev domaininvestigation.EvidenceRef) (ai.Fact, bool) {
	switch ev.SourceType {
	case domaininvestigation.EntityFinding:
		if f, err := s.findings.GetByID(ctx, ev.SourceID); err == nil {
			return findingToFact(f), true
		}
	case domaininvestigation.EntityAsset:
		if a, err := s.assets.GetByID(ctx, ev.SourceID); err == nil {
			return assetToFact(a), true
		}
	case domaininvestigation.EntityAlert:
		if a, err := s.alerts.GetAlertByID(ctx, ev.SourceID); err == nil {
			return alertToFact(a), true
		}
	case domaininvestigation.EntityDetectionMatch:
		if m, err := s.matches.GetMatchByID(ctx, ev.SourceID); err == nil {
			ruleName := ""
			if r, err := s.rules.GetRuleByID(ctx, m.RuleID); err == nil {
				ruleName = r.Name
			}
			return detectionToFact(m, ruleName), true
		}
	case domaininvestigation.EntityCorrelation:
		if c, err := s.correlations.GetCorrelationByID(ctx, ev.SourceID); err == nil {
			return correlationToFact(c), true
		}
	}
	return ai.Fact{}, false
}

// BuildAlertContext gathers one alert, its underlying detection match
// (phase13.md §20's "rule involved"), and the rule's own metadata.
func (s *Service) BuildAlertContext(ctx context.Context, alertID uuid.UUID) (ai.Context, error) {
	a, err := s.alerts.GetAlertByID(ctx, alertID)
	if err != nil {
		return ai.Context{}, err
	}
	facts := []ai.Fact{alertToFact(a)}

	if m, err := s.matches.GetMatchByID(ctx, a.DetectionMatchID); err == nil {
		ruleName := ""
		if r, err := s.rules.GetRuleByID(ctx, m.RuleID); err == nil {
			ruleName = r.Name
		}
		facts = append(facts, detectionToFact(m, ruleName))
	}

	var invID *uuid.UUID
	if a.InvestigationID != nil {
		invID = a.InvestigationID
	}
	return buildContext(a.TargetID, invID, facts, s.cfg.Limits), nil
}

// BuildDetectionContext gathers one detection match and its rule.
func (s *Service) BuildDetectionContext(ctx context.Context, matchID uuid.UUID) (ai.Context, error) {
	m, err := s.matches.GetMatchByID(ctx, matchID)
	if err != nil {
		return ai.Context{}, err
	}
	ruleName := ""
	if r, err := s.rules.GetRuleByID(ctx, m.RuleID); err == nil {
		ruleName = r.Name
	}
	facts := []ai.Fact{detectionToFact(m, ruleName)}
	return buildContext(m.TargetID, nil, facts, s.cfg.Limits), nil
}

// BuildCorrelationContext gathers one correlation's full graph and
// attack chain (phase13.md §22/§23).
func (s *Service) BuildCorrelationContext(ctx context.Context, correlationID uuid.UUID) (ai.Context, error) {
	// dataSource.GetCorrelation enforces TargetID scoping against the
	// caller's scope; here we ARE the trusted internal caller building
	// the initial context, so we first fetch the correlation directly to
	// learn its own TargetID, then reuse the same fact-assembly path with
	// that TargetID as the enforced scope — this avoids duplicating the
	// graph-walking logic between the tool and the context builder.
	c, err := s.correlations.GetCorrelationByID(ctx, correlationID)
	if err != nil {
		return ai.Context{}, err
	}
	facts, err := dataSource{svc: s}.GetCorrelation(ctx, ai.ToolScope{TargetID: c.TargetID.String()}, correlationID.String())
	if err != nil {
		return ai.Context{}, err
	}

	var invID *uuid.UUID
	if c.InvestigationID != nil {
		invID = c.InvestigationID
	}
	return buildContext(c.TargetID, invID, facts, s.cfg.Limits), nil
}

// BuildTargetContext gathers a general-purpose evidence set for a target
// not yet scoped to any single investigation/alert/correlation — used by
// AnalyzeTimeline/SummarizeIntelligence/IdentifyEvidenceGaps/
// GenerateInvestigationQuestions when called directly against a target
// (phase13.md's task list is not exclusively investigation-scoped).
func (s *Service) BuildTargetContext(ctx context.Context, targetID uuid.UUID) (ai.Context, error) {
	limit := s.cfg.Limits.Effective().MaxFactsPerType

	var facts []ai.Fact
	ds := dataSource{svc: s}
	scope := ai.ToolScope{TargetID: targetID.String()}

	if f, err := ds.GetFindings(ctx, scope, limit); err == nil {
		facts = append(facts, f...)
	}
	if f, err := ds.GetAssets(ctx, scope, limit); err == nil {
		facts = append(facts, f...)
	}
	if f, err := ds.GetIntelligence(ctx, scope, limit); err == nil {
		facts = append(facts, f...)
	}

	return buildContext(targetID, nil, facts, s.cfg.Limits), nil
}

// resolveOrCheckTarget fills in req.TargetID from the built Context when
// the caller didn't already supply one (the common CLI case — a caller
// naming only an investigation/alert/detection/correlation id doesn't
// need to separately resolve its target first), or, when a TargetID was
// already supplied, verifies it actually matches — defense in depth on
// top of dataSource's own scoping checks (phase13.md §61's test category
// exercises exactly this).
func resolveOrCheckTarget(req *TaskRequest, contextTargetID string) error {
	id, err := uuid.Parse(contextTargetID)
	if err != nil {
		return apperrors.NewInternal("built AI context carries an invalid target id", err)
	}
	if req.TargetID == uuid.Nil {
		req.TargetID = id
		return nil
	}
	if req.TargetID != id {
		return apperrors.NewForbidden("the requested resource does not belong to the expected target", nil)
	}
	return nil
}
