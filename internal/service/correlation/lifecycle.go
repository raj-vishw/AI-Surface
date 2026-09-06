package correlation

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	domaincorrelation "ai-recon-platform/internal/domain/correlation"
	apperrors "ai-recon-platform/internal/errors"
	correlationrepo "ai-recon-platform/internal/repository/correlation"
	"ai-recon-platform/internal/repository/pagination"
)

// GetCorrelation returns a correlation by id.
func (s *Service) GetCorrelation(ctx context.Context, id uuid.UUID) (domaincorrelation.Correlation, error) {
	return s.correlations.GetCorrelationByID(ctx, id)
}

// ListCorrelations returns a page of correlations matching filter.
func (s *Service) ListCorrelations(ctx context.Context, filter correlationrepo.ListFilter) (pagination.Page[domaincorrelation.Correlation], error) {
	return s.correlations.ListCorrelations(ctx, filter)
}

// ListNodes returns every node (= evidence reference) attached to
// correlationID.
func (s *Service) ListNodes(ctx context.Context, correlationID uuid.UUID) ([]domaincorrelation.Node, error) {
	return s.nodes.ListNodes(ctx, correlationID)
}

// ListEdges returns every edge belonging to correlationID.
func (s *Service) ListEdges(ctx context.Context, correlationID uuid.UUID) ([]domaincorrelation.Edge, error) {
	return s.edges.ListEdges(ctx, correlationID)
}

// GetChain returns the AttackChain for correlationID, if one was
// produced (phase12.md §44 — not every correlation classifies into a
// chain).
func (s *Service) GetChain(ctx context.Context, correlationID uuid.UUID) (domaincorrelation.AttackChain, []domaincorrelation.AttackChainStage, error) {
	chain, err := s.chains.GetChainByCorrelationID(ctx, correlationID)
	if err != nil {
		return domaincorrelation.AttackChain{}, nil, err
	}
	stages, err := s.stages.ListStages(ctx, chain.ID)
	if err != nil {
		return domaincorrelation.AttackChain{}, nil, err
	}
	return chain, stages, nil
}

// GetChainByID returns one attack chain and its stages by the chain's
// own id.
func (s *Service) GetChainByID(ctx context.Context, id uuid.UUID) (domaincorrelation.AttackChain, []domaincorrelation.AttackChainStage, error) {
	chain, err := s.chains.GetChainByID(ctx, id)
	if err != nil {
		return domaincorrelation.AttackChain{}, nil, err
	}
	stages, err := s.stages.ListStages(ctx, chain.ID)
	if err != nil {
		return domaincorrelation.AttackChain{}, nil, err
	}
	return chain, stages, nil
}

// ListChains returns a page of every attack chain.
func (s *Service) ListChains(ctx context.Context, pageParams pagination.Params) (pagination.Page[domaincorrelation.AttackChain], error) {
	return s.chains.ListChains(ctx, pageParams)
}

// Confirm transitions a correlation to StatusConfirmed — the only
// system-recognized way a correlation ever becomes a stated "confirmed"
// finding (phase12.md §46/§47): always requires an actor.
func (s *Service) Confirm(ctx context.Context, id uuid.UUID, confirmedBy, notes string) (domaincorrelation.Correlation, error) {
	if confirmedBy == "" {
		return domaincorrelation.Correlation{}, apperrors.NewValidation("confirmedBy is required", nil)
	}
	return s.correlations.Confirm(ctx, id, confirmedBy, notes)
}

// Dismiss transitions a correlation to StatusDismissed — always requires
// a reason (phase12.md §48).
func (s *Service) Dismiss(ctx context.Context, id uuid.UUID, dismissedBy, reason string) (domaincorrelation.Correlation, error) {
	if reason == "" {
		return domaincorrelation.Correlation{}, apperrors.NewValidation("a dismissal reason is required", nil)
	}
	return s.correlations.Dismiss(ctx, id, dismissedBy, reason)
}

// Merge absorbs every correlation in sourceIDs into survivorID
// (phase12.md §29): the survivor's MergedFromIDs grows to record every
// absorbed id, and each absorbed correlation's own row, evidence, and
// edges are preserved unmodified except for MergedIntoID — nothing is
// deleted. Runs inside one transaction so a partial merge is never
// visible.
func (s *Service) Merge(ctx context.Context, survivorID uuid.UUID, sourceIDs []uuid.UUID) (domaincorrelation.Correlation, error) {
	if len(sourceIDs) == 0 {
		return domaincorrelation.Correlation{}, apperrors.NewValidation("at least one source correlation id is required", nil)
	}
	var result domaincorrelation.Correlation
	err := s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		repo := correlationrepo.NewPostgresRepository(tx)
		if _, err := repo.GetCorrelationByID(ctx, survivorID); err != nil {
			return err
		}
		for _, sourceID := range sourceIDs {
			if sourceID == survivorID {
				continue
			}
			if _, err := repo.GetCorrelationByID(ctx, sourceID); err != nil {
				return err
			}
			nodes, err := repo.ListNodes(ctx, sourceID)
			if err != nil {
				return err
			}
			nodeIDs := make([]uuid.UUID, len(nodes))
			for i, n := range nodes {
				nodeIDs[i] = n.ID
			}
			if err := repo.ReassignNodes(ctx, nodeIDs, survivorID); err != nil {
				return err
			}
			edges, err := repo.EdgesTouching(ctx, nodeIDs)
			if err != nil {
				return err
			}
			edgeIDs := make([]uuid.UUID, 0, len(edges))
			for _, e := range edges {
				edgeIDs = append(edgeIDs, e.ID)
			}
			if err := repo.ReassignEdges(ctx, edgeIDs, survivorID); err != nil {
				return err
			}
			if _, err := repo.MarkMergedInto(ctx, sourceID, survivorID); err != nil {
				return err
			}
		}
		updated, err := repo.AppendMergedFrom(ctx, survivorID, sourceIDs)
		if err != nil {
			return err
		}
		result = updated
		return nil
	})
	return result, err
}

// Split moves the given evidence nodes out of an existing correlation
// into a brand-new one (phase12.md §30) — the original correlation's
// history is preserved (it keeps every node not reassigned, plus its own
// unmodified id/fingerprint/timestamps); the new correlation records
// SplitFromID so the relationship remains visible. Runs inside one
// transaction.
func (s *Service) Split(ctx context.Context, originalID uuid.UUID, nodeIDs []uuid.UUID, title, actorID string) (domaincorrelation.Correlation, error) {
	if len(nodeIDs) == 0 {
		return domaincorrelation.Correlation{}, apperrors.NewValidation("at least one node id is required to split", nil)
	}
	var result domaincorrelation.Correlation
	err := s.pool.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		repo := correlationrepo.NewPostgresRepository(tx)
		original, err := repo.GetCorrelationByID(ctx, originalID)
		if err != nil {
			return err
		}
		if title == "" {
			title = "Split from: " + original.Title
		}
		newCorrelation := domaincorrelation.Correlation{
			TargetID: original.TargetID, Title: title, Description: "Split out of correlation " + original.ID.String() + " by " + actorID + ".",
			Status: domaincorrelation.StatusOpen, Severity: original.Severity, Confidence: original.Confidence, Score: original.Score,
			Fingerprint: original.Fingerprint + "-split-" + uuid.NewString(), ModelVersion: domaincorrelation.ModelVersion,
			FirstObservedAt: original.FirstObservedAt, LastObservedAt: original.LastObservedAt,
			SplitFromID: &originalID,
		}
		if err := newCorrelation.Validate(); err != nil {
			return apperrors.NewValidation("invalid split correlation", err)
		}
		created, err := repo.CreateCorrelation(ctx, newCorrelation)
		if err != nil {
			return err
		}
		if err := repo.ReassignNodes(ctx, nodeIDs, created.ID); err != nil {
			return err
		}
		edges, err := repo.EdgesTouching(ctx, nodeIDs)
		if err != nil {
			return err
		}
		edgeIDs := make([]uuid.UUID, 0, len(edges))
		for _, e := range edges {
			edgeIDs = append(edgeIDs, e.ID)
		}
		if err := repo.ReassignEdges(ctx, edgeIDs, created.ID); err != nil {
			return err
		}
		result = created
		return nil
	})
	return result, err
}
