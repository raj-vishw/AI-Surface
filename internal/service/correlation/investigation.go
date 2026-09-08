package correlation

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	domaincorrelation "ai-recon-platform/internal/domain/correlation"
	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	apperrors "ai-recon-platform/internal/errors"
)

// toInvestigationEntity maps a correlation node's type onto Phase 9's
// EntityType vocabulary — mirrors internal/service/rule's identical
// mapping for DetectionMatch evidence (toInvestigationEntity in
// alerts.go).
func toInvestigationEntity(t domaincorrelation.NodeType) domaininvestigation.EntityType {
	switch t {
	case domaincorrelation.NodeFinding:
		return domaininvestigation.EntityFinding
	case domaincorrelation.NodeAsset:
		return domaininvestigation.EntityAsset
	case domaincorrelation.NodeEndpoint:
		return domaininvestigation.EntityEndpoint
	case domaincorrelation.NodeDetectionMatch:
		return domaininvestigation.EntityDetectionMatch
	case domaincorrelation.NodeAlert:
		return domaininvestigation.EntityAlert
	default:
		return "" // intelligence records/investigations have no matching evidence entity type — skipped, not fabricated
	}
}

func severityToPriority(sev domaincorrelation.Severity) domaininvestigation.Priority {
	switch sev {
	case domaincorrelation.SeverityCritical:
		return domaininvestigation.PriorityUrgent
	case domaincorrelation.SeverityHigh:
		return domaininvestigation.PriorityHigh
	case domaincorrelation.SeverityMedium:
		return domaininvestigation.PriorityNormal
	default:
		return domaininvestigation.PriorityLow
	}
}

// AttachToInvestigation creates a Phase 9 investigation from a
// correlation, attaches every node as evidence, and records timeline
// events for the correlation (and, if one exists, its attack chain) —
// phase12.md §35's "a correlation should be attachable to an
// investigation", mirroring internal/service/rule.PromoteToInvestigation
// exactly.
func (s *Service) AttachToInvestigation(ctx context.Context, correlationID uuid.UUID, actorID string) (domaininvestigation.Investigation, error) {
	c, err := s.correlations.GetCorrelationByID(ctx, correlationID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}
	if c.InvestigationID != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("correlation is already attached to an investigation", nil)
	}
	nodes, err := s.nodes.ListNodes(ctx, correlationID)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	inv := domaininvestigation.Investigation{
		TargetID: c.TargetID, Title: c.Title, Description: c.Description,
		Status: domaininvestigation.StatusOpen, Priority: severityToPriority(c.Severity),
		Severity: domaininvestigation.Severity(c.Severity), Confidence: domaincorrelationToInvestigationConfidence(c.Confidence),
		CreatedBy: actorID, DetectedAt: &c.FirstObservedAt, FirstObservedAt: &c.FirstObservedAt, LastObservedAt: &c.LastObservedAt,
	}
	if err := inv.Validate(); err != nil {
		return domaininvestigation.Investigation{}, apperrors.NewValidation("invalid investigation", err)
	}
	created, err := s.investigations.Create(ctx, inv)
	if err != nil {
		return domaininvestigation.Investigation{}, err
	}

	for _, n := range nodes {
		entityType := toInvestigationEntity(n.Type)
		if entityType == "" {
			continue
		}
		if _, _, err := s.investigations.AttachEvidence(ctx, domaininvestigation.EvidenceRef{
			InvestigationID: created.ID, SourceType: entityType, SourceID: n.ReferenceID, ObservedAt: n.Timestamp, AddedBy: actorID,
		}); err != nil {
			s.logger.Error("investigation_evidence_attach_failed", "investigation_id", created.ID, "source_id", n.ReferenceID, "error", err)
		}
	}

	if _, err := s.investigations.AppendEvent(ctx, domaininvestigation.TimelineEvent{
		TargetID: c.TargetID, InvestigationID: created.ID, Timestamp: c.FirstObservedAt,
		Type: domaininvestigation.EventCorrelationAttached, SourceType: domaininvestigation.EntityCorrelation, SourceID: &c.ID,
		Title: "Correlation attached", Description: c.Description, Severity: string(c.Severity), Actor: actorID,
	}); err != nil {
		s.logger.Error("investigation_timeline_append_failed", "investigation_id", created.ID, "error", err)
	}

	if chain, _, err := s.GetChain(ctx, correlationID); err == nil {
		if _, err := s.investigations.AppendEvent(ctx, domaininvestigation.TimelineEvent{
			TargetID: c.TargetID, InvestigationID: created.ID, Timestamp: c.FirstObservedAt,
			Type: domaininvestigation.EventAttackChainCreated, SourceType: domaininvestigation.EntityAttackChain, SourceID: &chain.ID,
			Title: fmt.Sprintf("Attack chain %q attached", chain.Name), Description: chain.Description, Severity: string(chain.Severity), Actor: actorID,
		}); err != nil {
			s.logger.Error("investigation_timeline_append_failed", "investigation_id", created.ID, "error", err)
		}
	}

	if _, err := s.correlations.SetInvestigation(ctx, correlationID, created.ID); err != nil {
		s.logger.Error("correlation_set_investigation_failed", "correlation_id", correlationID, "error", err)
	}

	return created, nil
}

// domaincorrelationToInvestigationConfidence maps Phase 12's three-level
// confidence onto Phase 9's five-level scale — a documented, one-way
// widening (never claims more precision than the correlation itself has).
func domaincorrelationToInvestigationConfidence(c domaincorrelation.Confidence) domaininvestigation.Confidence {
	switch c {
	case domaincorrelation.ConfidenceHigh:
		return domaininvestigation.ConfidenceHigh
	case domaincorrelation.ConfidenceMedium:
		return domaininvestigation.ConfidenceMedium
	default:
		return domaininvestigation.ConfidenceLow
	}
}
