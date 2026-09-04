package investigation

import (
	"context"

	"github.com/google/uuid"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
)

// CreateHypothesis records a new analyst hypothesis (phase9.md §24) and a
// hypothesis_created timeline entry.
func (s *Service) CreateHypothesis(ctx context.Context, investigationID uuid.UUID, title, description, createdBy string) (domaininvestigation.Hypothesis, error) {
	h := domaininvestigation.Hypothesis{
		InvestigationID: investigationID, Title: title, Description: description,
		Status: domaininvestigation.HypothesisProposed, CreatedBy: createdBy,
	}
	if err := h.Validate(); err != nil {
		return domaininvestigation.Hypothesis{}, err
	}
	result, err := s.hypotheses.CreateHypothesis(ctx, h)
	if err != nil {
		return domaininvestigation.Hypothesis{}, err
	}

	if inv, err := s.investigations.GetByID(ctx, investigationID); err == nil {
		hid := result.ID
		s.recordEvent(ctx, inv, domaininvestigation.EventHypothesisCreated, "Hypothesis proposed: "+title, "", createdBy, &hid)
	}
	return result, nil
}

// GetHypothesis returns one hypothesis.
func (s *Service) GetHypothesis(ctx context.Context, id uuid.UUID) (domaininvestigation.Hypothesis, error) {
	return s.hypotheses.GetHypothesis(ctx, id)
}

// ListHypotheses returns every hypothesis for an investigation.
func (s *Service) ListHypotheses(ctx context.Context, investigationID uuid.UUID) ([]domaininvestigation.Hypothesis, error) {
	return s.hypotheses.ListHypotheses(ctx, investigationID)
}

// UpdateHypothesisStatus transitions a hypothesis's own status (phase9.md
// §24), independent of the parent investigation's status.
func (s *Service) UpdateHypothesisStatus(ctx context.Context, id uuid.UUID, status domaininvestigation.HypothesisStatus, confidence domaininvestigation.Confidence, actorID string) (domaininvestigation.Hypothesis, error) {
	h, err := s.hypotheses.UpdateHypothesisStatus(ctx, id, status, confidence)
	if err != nil {
		return domaininvestigation.Hypothesis{}, err
	}
	if inv, err := s.investigations.GetByID(ctx, h.InvestigationID); err == nil {
		hid := h.ID
		s.recordEvent(ctx, inv, domaininvestigation.EventHypothesisUpdated, "Hypothesis status changed to "+string(status)+": "+h.Title, "", actorID, &hid)
	}
	return h, nil
}

// AddHypothesisEvidence records one explicit, cited piece of support for
// a hypothesis (phase9.md §25) — never bare speculation, enforced by
// HypothesisEvidence.Validate requiring a non-empty description.
func (s *Service) AddHypothesisEvidence(ctx context.Context, hypothesisID uuid.UUID, sourceType domaininvestigation.EntityType, sourceID uuid.UUID, description string) (domaininvestigation.HypothesisEvidence, error) {
	e := domaininvestigation.HypothesisEvidence{HypothesisID: hypothesisID, SourceType: sourceType, SourceID: sourceID, Description: description}
	if err := e.Validate(); err != nil {
		return domaininvestigation.HypothesisEvidence{}, err
	}
	return s.hypotheses.AddHypothesisEvidence(ctx, e)
}

// ListHypothesisEvidence returns every evidence item for a hypothesis.
func (s *Service) ListHypothesisEvidence(ctx context.Context, hypothesisID uuid.UUID) ([]domaininvestigation.HypothesisEvidence, error) {
	return s.hypotheses.ListHypothesisEvidence(ctx, hypothesisID)
}
