package correlation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/correlation"
	domaincorrelation "ai-surface-platform/internal/domain/correlation"
	apperrors "ai-surface-platform/internal/errors"
)

// EvaluateResult is one Evaluate call's outcome.
type EvaluateResult struct {
	ObservationsConsidered int
	ComponentsFound        int
	Correlations           []domaincorrelation.Correlation
	Truncated              bool
	Duration               time.Duration
	DryRun                 bool
}

// componentEarliest returns the earliest node timestamp in g — used only
// to anchor ComputeFingerprint's window bucket (see
// internal/correlation.ComputeFingerprint).
func componentEarliest(g correlation.Graph) time.Time {
	var earliest time.Time
	for _, n := range g.Nodes {
		if earliest.IsZero() || n.Timestamp.Before(earliest) {
			earliest = n.Timestamp
		}
	}
	return earliest
}

func nodeTypeToDomain(t correlation.NodeType) domaincorrelation.NodeType {
	return domaincorrelation.NodeType(t)
}

// Evaluate runs the correlation engine over targetID's observations
// within [from, to) (phase12.md §24/§64) and, unless dryRun, persists
// every resulting connected component as its own Correlation (with its
// node/edge graph and, when it classifies into at least one stage, an
// attack chain) — deduplicated by fingerprint exactly like Phase 11's
// DetectionMatch.Evaluate.
func (s *Service) Evaluate(ctx context.Context, targetID uuid.UUID, from, to time.Time, dryRun bool) (EvaluateResult, error) {
	start := time.Now()

	if to.Sub(from) > s.cfg.EffectiveHistoricalMaxRange() {
		return EvaluateResult{}, apperrors.NewValidation(
			fmt.Sprintf("requested range %s exceeds the maximum correlation evaluation range %s", to.Sub(from), s.cfg.EffectiveHistoricalMaxRange()), nil)
	}

	observations, err := s.buildObservations(ctx, targetID, from, to)
	if err != nil {
		return EvaluateResult{}, err
	}

	input := correlation.Input{TargetID: targetID, Observations: observations, Config: s.cfg}
	engineResult := s.engine.Correlate(ctx, input)
	for _, e := range engineResult.Errors {
		s.logger.Error("correlation_strategy_failed", "strategy_id", e.StrategyID, "target_id", targetID, "error", e.Err)
	}

	graph := correlation.BuildGraph(observations, engineResult.Edges, s.cfg)
	components := correlation.ConnectedComponents(graph)

	result := EvaluateResult{
		ObservationsConsidered: len(observations), ComponentsFound: len(components),
		Truncated: engineResult.Truncated || graph.NodeLimited || graph.EdgeLimited, DryRun: dryRun,
	}
	if dryRun {
		result.Duration = time.Since(start)
		return result, nil
	}

	for _, component := range components {
		saved, err := s.persistComponent(ctx, targetID, component)
		if err != nil {
			s.logger.Error("correlation_persist_failed", "target_id", targetID, "error", err)
			continue
		}
		result.Correlations = append(result.Correlations, saved)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// persistComponent scores, explains, and persists one connected
// component as a Correlation, its nodes/edges, and — when at least one
// stage classifies — an AttackChain.
func (s *Service) persistComponent(ctx context.Context, targetID uuid.UUID, component correlation.Graph) (domaincorrelation.Correlation, error) {
	score := correlation.Score(component)
	confidence := correlation.ConfidenceForScore(score)
	severity := correlation.DeriveSeverity(component, confidence)
	window := s.cfg.EffectiveTemporalWindow()
	fingerprint := correlation.ComputeFingerprint(targetID, component, componentEarliest(component), window)
	explanation := correlation.Explain(component, score, confidence, window)

	first, last := component.Nodes[0].Timestamp, component.Nodes[0].Timestamp
	for _, n := range component.Nodes {
		if n.Timestamp.Before(first) {
			first = n.Timestamp
		}
		if n.Timestamp.After(last) {
			last = n.Timestamp
		}
	}

	c := domaincorrelation.Correlation{
		TargetID: targetID, Title: correlationTitle(component), Description: explanation,
		Status: domaincorrelation.StatusOpen, Severity: domaincorrelation.Severity(severity),
		Confidence: domaincorrelation.Confidence(confidence), Score: score,
		Fingerprint: fingerprint, ModelVersion: domaincorrelation.ModelVersion,
		FirstObservedAt: first, LastObservedAt: last,
	}
	if err := c.Validate(); err != nil {
		return domaincorrelation.Correlation{}, apperrors.NewValidation("invalid correlation", err)
	}

	saved, _, err := s.correlations.UpsertCorrelation(ctx, c)
	if err != nil {
		return domaincorrelation.Correlation{}, err
	}

	nodeIDs := map[string]uuid.UUID{}
	for _, n := range component.Nodes {
		role := domaincorrelation.RoleSupporting
		if isTrigger(component, n.Ref) {
			role = domaincorrelation.RoleTrigger
		}
		savedNode, _, err := s.nodes.CreateNode(ctx, domaincorrelation.Node{
			CorrelationID: saved.ID, Type: nodeTypeToDomain(n.Ref.Type), ReferenceID: n.Ref.ReferenceID,
			Role: role, Timestamp: n.Timestamp, Attributes: n.Attributes,
		})
		if err != nil {
			s.logger.Error("correlation_node_persist_failed", "correlation_id", saved.ID, "error", err)
			continue
		}
		nodeIDs[n.Ref.Key()] = savedNode.ID
	}

	for _, e := range component.Edges {
		sourceID, sourceOK := nodeIDs[e.Source.Key()]
		targetNodeID, targetOK := nodeIDs[e.Target.Key()]
		if !sourceOK || !targetOK {
			continue
		}
		if _, _, err := s.edges.CreateEdge(ctx, domaincorrelation.Edge{
			CorrelationID: saved.ID, SourceNodeID: sourceID, TargetNodeID: targetNodeID,
			Relationship: domaincorrelation.Relationship(e.Relationship), Provenance: domaincorrelation.Provenance(e.Provenance),
			Confidence: domaincorrelation.EdgeConfidence(e.Confidence), Evidence: e.Evidence,
			StrategyID: e.StrategyID, StrategyVersion: e.StrategyVersion,
		}); err != nil {
			s.logger.Error("correlation_edge_persist_failed", "correlation_id", saved.ID, "error", err)
		}
	}

	if err := s.persistChain(ctx, saved, component, nodeIDs); err != nil {
		s.logger.Error("attack_chain_persist_failed", "correlation_id", saved.ID, "error", err)
	}

	return saved, nil
}

// isTrigger reports whether ref is the source or target of at least one
// edge with Provenance observed — an observed edge means this node was
// directly established as relevant (an asset a finding was recorded
// against, say), as opposed to a node only ever linked by inference.
func isTrigger(g correlation.Graph, ref correlation.NodeRef) bool {
	for _, e := range g.Edges {
		if (e.Source == ref || e.Target == ref) && e.Provenance == correlation.ProvenanceObserved {
			return true
		}
	}
	return false
}

// correlationTitle builds a short, factual title — never a "confirmed
// attack" claim (phase12.md §3/§46).
func correlationTitle(g correlation.Graph) string {
	return fmt.Sprintf("Correlated activity across %d observation(s)", len(g.Nodes))
}
