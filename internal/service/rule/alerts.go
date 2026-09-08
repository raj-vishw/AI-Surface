package rule

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	domainrule "ai-recon-platform/internal/domain/rule"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	rulerepo "ai-recon-platform/internal/repository/rule"
)

// GetAlert returns an alert by id.
func (s *Service) GetAlert(ctx context.Context, id uuid.UUID) (domainrule.Alert, error) {
	return s.alerts.GetAlertByID(ctx, id)
}

// ListAlerts returns a page of alerts matching filter.
func (s *Service) ListAlerts(ctx context.Context, filter rulerepo.AlertListFilter) (pagination.Page[domainrule.Alert], error) {
	return s.alerts.ListAlerts(ctx, filter)
}

// GetMatch returns a detection match by id.
func (s *Service) GetMatch(ctx context.Context, id uuid.UUID) (domainrule.DetectionMatch, error) {
	return s.matches.GetMatchByID(ctx, id)
}

// ListMatches returns a page of detection matches matching filter.
func (s *Service) ListMatches(ctx context.Context, filter rulerepo.MatchListFilter) (pagination.Page[domainrule.DetectionMatch], error) {
	return s.matches.ListMatches(ctx, filter)
}

// ListEvidence returns every event attached to a match.
func (s *Service) ListEvidence(ctx context.Context, matchID uuid.UUID) ([]domainrule.MatchEvidence, error) {
	return s.evidence.ListByMatch(ctx, matchID)
}

// AcknowledgeAlert transitions an alert to acknowledged (phase11.md
// §21) — every status change is itself auditable via the returned row's
// UpdatedAt; a full analyst-action audit trail (who, when, why) beyond
// status+timestamp would require this platform's own authentication/
// authorization layer, which does not exist (see docs/architecture/
// detection-engine.md's Known Limitations). ResolveAlert/SuppressAlert
// below are the same kind of lifecycle transition.
func (s *Service) AcknowledgeAlert(ctx context.Context, id uuid.UUID) (domainrule.Alert, error) {
	return s.alerts.UpdateAlertStatus(ctx, id, domainrule.AlertAcknowledged)
}

// ResolveAlert marks an alert resolved. It never mutates or removes the
// underlying DetectionMatch/evidence.
func (s *Service) ResolveAlert(ctx context.Context, id uuid.UUID) (domainrule.Alert, error) {
	return s.alerts.UpdateAlertStatus(ctx, id, domainrule.AlertResolved)
}

// SuppressAlert marks an alert suppressed AND records a Suppression row
// scoped to it (phase11.md §35/§36) — reason is always required.
func (s *Service) SuppressAlert(ctx context.Context, id uuid.UUID, reason, actorID string, duration time.Duration) (domainrule.Alert, error) {
	if _, err := s.createSuppression(ctx, domainrule.ScopeAlert, id, reason, actorID, duration); err != nil {
		return domainrule.Alert{}, err
	}
	return s.alerts.UpdateAlertStatus(ctx, id, domainrule.AlertSuppressed)
}

// PromoteToInvestigation creates a Phase 9 investigation from an alert,
// automatically attaching the underlying detection match's evidence and
// recording a timeline event (phase11.md §22/§99) — the analyst never
// needs to manually reconstruct the evidence chain.
func (s *Service) PromoteToInvestigation(ctx context.Context, alertID uuid.UUID, actorID string) (domaininvestigation.Investigation, error) {
	alert, err := s.alerts.GetAlertByID(ctx, alertID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	if alert.InvestigationID != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("alert is already attached to an investigation", nil)
	}
	match, err := s.matches.GetMatchByID(ctx, alert.DetectionMatchID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	r, err := s.rules.GetRuleByID(ctx, match.RuleID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	evidenceRows, err := s.evidence.ListByMatch(ctx, match.ID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	inv := domaininvestigation.Investigation{
		TargetID: alert.TargetID, Title: alert.Title,
		Description: fmt.Sprintf("Promoted from alert triggered by rule %q (version %d).\n\n%s", r.Name, match.RuleVersion, match.Explanation),
		Status:      domaininvestigation.StatusOpen, Priority: severityToPriority(match.Severity),
		Severity: domaininvestigation.Severity(match.Severity), Confidence: domaininvestigation.Confidence(match.Confidence),
		CreatedBy: actorID, DetectedAt: &match.FirstObservedAt, FirstObservedAt: &match.FirstObservedAt, LastObservedAt: &match.LastObservedAt,
	}
	if err := inv.Validate(); err != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("invalid investigation", err)
	}
	created, err := s.investigations.Create(ctx, inv)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	for _, ev := range evidenceRows {
		entityType := toInvestigationEntity(ev.SourceType)
		if entityType == "" {
			continue
		}
		_, _, err := s.investigations.AttachEvidence(ctx, domaininvestigation.EvidenceRef{
			InvestigationID: created.ID, SourceType: entityType, SourceID: ev.SourceID, ObservedAt: ev.ObservedAt, AddedBy: actorID,
		})
		if err != nil {
			s.logger.Error("investigation_evidence_attach_failed", "investigation_id", created.ID, "source_id", ev.SourceID, "error", err)
		}
	}
	_, _, err = s.investigations.AttachEvidence(ctx, domaininvestigation.EvidenceRef{
		InvestigationID: created.ID, SourceType: domaininvestigation.EntityDetectionMatch, SourceID: match.ID, ObservedAt: match.FirstObservedAt, AddedBy: actorID,
	})
	if err != nil {
		s.logger.Error("investigation_evidence_attach_failed", "investigation_id", created.ID, "source_id", match.ID, "error", err)
	}

	_, err = s.investigations.AppendEvent(ctx, domaininvestigation.TimelineEvent{
		TargetID: alert.TargetID, InvestigationID: created.ID, Timestamp: match.FirstObservedAt,
		Type: domaininvestigation.EventDetectionMatchCreated, SourceType: domaininvestigation.EntityDetectionMatch, SourceID: &match.ID,
		Title: fmt.Sprintf("Detection match from rule %q attached", r.Name), Description: match.Explanation,
		Severity: string(match.Severity), Actor: actorID,
	})
	if err != nil {
		s.logger.Error("investigation_timeline_append_failed", "investigation_id", created.ID, "error", err)
	}

	if _, err := s.alerts.SetInvestigation(ctx, alertID, created.ID); err != nil {
		s.logger.Error("alert_investigation_link_failed", "alert_id", alertID, "investigation_id", created.ID, "error", err)
	}

	return s.investigations.GetByID(ctx, created.ID)
}

func severityToPriority(s domainrule.Severity) domaininvestigation.Priority {
	switch s {
	case domainrule.SeverityCritical:
		return domaininvestigation.PriorityUrgent
	case domainrule.SeverityHigh:
		return domaininvestigation.PriorityHigh
	case domainrule.SeverityMedium:
		return domaininvestigation.PriorityNormal
	default:
		return domaininvestigation.PriorityLow
	}
}

func toInvestigationEntity(t domainrule.SourceType) domaininvestigation.EntityType {
	switch t {
	case domainrule.SourceFinding:
		return domaininvestigation.EntityFinding
	case domainrule.SourceAssetObservation:
		return domaininvestigation.EntityAsset
	case domainrule.SourceEndpointObservation:
		return domaininvestigation.EntityEndpoint
	case domainrule.SourceFingerprintChange:
		return domaininvestigation.EntityTechnology
	default:
		return "" // intelligence records have no matching investigation entity type yet — skipped, not fabricated
	}
}

// Suppress creates a Suppression covering scope/scopeID (phase11.md
// §35/§36) — reason is always required, duration <= 0 means indefinite.
func (s *Service) Suppress(ctx context.Context, scope domainrule.SuppressionScope, scopeID uuid.UUID, reason, actorID string, duration time.Duration) (domainrule.Suppression, error) {
	return s.createSuppression(ctx, scope, scopeID, reason, actorID, duration)
}

func (s *Service) createSuppression(ctx context.Context, scope domainrule.SuppressionScope, scopeID uuid.UUID, reason, actorID string, duration time.Duration) (domainrule.Suppression, error) {
	sup := domainrule.Suppression{Scope: scope, ScopeID: scopeID, Reason: reason, CreatedBy: actorID}
	if duration > 0 {
		expires := time.Now().UTC().Add(duration)
		sup.ExpiresAt = &expires
	}
	// TargetID is resolved from the scope's own row so callers never
	// need to pass it redundantly.
	targetID, err := s.targetIDForScope(ctx, scope, scopeID)
	if err != nil {
		return domainrule.Suppression{}, err
	}
	sup.TargetID = targetID
	if err := sup.Validate(); err != nil {
		return domainrule.Suppression{}, apperrors.NewValidation("invalid suppression", err)
	}
	return s.suppressions.CreateSuppression(ctx, sup)
}

func (s *Service) targetIDForScope(ctx context.Context, scope domainrule.SuppressionScope, scopeID uuid.UUID) (uuid.UUID, error) {
	switch scope {
	case domainrule.ScopeRule:
		r, err := s.rules.GetRuleByID(ctx, scopeID)
		return r.TargetID, err
	case domainrule.ScopeMatch:
		m, err := s.matches.GetMatchByID(ctx, scopeID)
		return m.TargetID, err
	case domainrule.ScopeAlert:
		a, err := s.alerts.GetAlertByID(ctx, scopeID)
		return a.TargetID, err
	default:
		return uuid.Nil, apperrors.NewValidation("unrecognized suppression scope", nil)
	}
}

// RemoveSuppression marks a suppression removed (phase11.md §37) — the
// row itself is preserved.
func (s *Service) RemoveSuppression(ctx context.Context, id uuid.UUID, actorID string) (domainrule.Suppression, error) {
	return s.suppressions.RemoveSuppression(ctx, id, actorID)
}

// ListSuppressions returns a page of suppressions matching filter.
func (s *Service) ListSuppressions(ctx context.Context, filter rulerepo.SuppressionListFilter) (pagination.Page[domainrule.Suppression], error) {
	return s.suppressions.ListSuppressions(ctx, filter)
}
