package correlation

import (
	"context"

	"github.com/google/uuid"

	"ai-surface-platform/internal/correlation"
	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	apperrors "ai-surface-platform/internal/errors"
)

// persistChain builds and persists an AttackChain for saved's component,
// when at least one stage classifies (phase12.md §44 — a component with
// no classifiable stage simply gets no chain at all; nothing is
// fabricated).
func (s *Service) persistChain(ctx context.Context, saved domaincorrelation.Correlation, component correlation.Graph, _ map[string]uuid.UUID) error {
	draft := correlation.BuildChain(component)
	if len(draft.Stages) == 0 {
		return nil
	}

	chain := domaincorrelation.AttackChain{
		CorrelationID: saved.ID, Name: chainName(), Description: saved.Description,
		Confidence: domaincorrelation.Confidence(draft.Confidence), Severity: saved.Severity, Status: domaincorrelation.StatusOpen,
	}
	if err := chain.Validate(); err != nil {
		return apperrors.NewValidation("invalid attack chain", err)
	}
	savedChain, err := s.chains.CreateChain(ctx, chain)
	if err != nil {
		return err
	}

	for i, stageDraft := range draft.Stages {
		evidence := make([]domaincorrelation.StageEvidenceRef, 0, len(stageDraft.Evidence))
		for _, ref := range stageDraft.Evidence {
			evidence = append(evidence, domaincorrelation.StageEvidenceRef{NodeType: nodeTypeToDomain(ref.Type), ReferenceID: ref.ReferenceID})
		}
		stage := domaincorrelation.AttackChainStage{
			AttackChainID: savedChain.ID, Stage: domaincorrelation.StageType(stageDraft.Stage), Order: i,
			Confidence: domaincorrelation.EdgeConfidence(stageDraft.Confidence), Evidence: evidence,
		}
		if err := stage.Validate(); err != nil {
			s.logger.Error("attack_chain_stage_invalid", "attack_chain_id", savedChain.ID, "stage", stageDraft.Stage, "error", err)
			continue
		}
		if _, err := s.stages.CreateStage(ctx, stage); err != nil {
			s.logger.Error("attack_chain_stage_persist_failed", "attack_chain_id", savedChain.ID, "error", err)
		}
	}
	return nil
}

// chainName produces a short, factual name — never a "confirmed attack"
// claim (phase12.md §3/§46).
func chainName() string { return "Correlated Activity Chain" }
