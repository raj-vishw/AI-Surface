// Package correlation implements persistence for the correlation domain
// model — mirroring internal/repository/rule's shape and conventions
// exactly (one PostgresRepository type implementing several narrow,
// entity-specific interfaces, never importing internal/correlation the
// engine). Attributes/Evidence payloads are stored as JSONB; a
// Edge's Evidence text and a Correlation's MergedFromIDs are
// the only places free-form content lives, and neither is ever executed
// or rendered as HTML.
package correlation

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/correlation"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows a correlation listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	TargetID   uuid.UUID
	Status     correlation.Status
	Severity   correlation.Severity
	Confidence correlation.Confidence
	Pagination pagination.Params
}

// Repository persists and queries Correlation rows.
type Repository interface {
	// UpsertCorrelation inserts c, or — if a row with the same
	// Fingerprint already exists — widens LastObservedAt to the later of
	// the two timestamps (phase12.md §27/§28's deduplication) without
	// touching Status, exactly like internal/repository/rule.
	// MatchRepository.UpsertMatch. created reports whether a new row was
	// inserted.
	UpsertCorrelation(ctx context.Context, c correlation.Correlation) (result correlation.Correlation, created bool, err error)
	// CreateCorrelation always inserts a new row — used by Split
	// (phase12.md §30), which creates a genuinely new correlation rather
	// than deduplicating against an existing one.
	CreateCorrelation(ctx context.Context, c correlation.Correlation) (correlation.Correlation, error)
	GetCorrelationByID(ctx context.Context, id uuid.UUID) (correlation.Correlation, error)
	ListCorrelations(ctx context.Context, filter ListFilter) (pagination.Page[correlation.Correlation], error)
	// UpdateStatus transitions status without requiring the
	// confirm/dismiss-specific fields Confirm/Dismiss populate.
	UpdateStatus(ctx context.Context, id uuid.UUID, status correlation.Status) (correlation.Correlation, error)
	// Confirm is the only way Status ever becomes StatusConfirmed
	// (phase12.md §47) — always requires confirmedBy.
	Confirm(ctx context.Context, id uuid.UUID, confirmedBy, notes string) (correlation.Correlation, error)
	// Dismiss is the only way Status ever becomes StatusDismissed
	// (phase12.md §48) — always requires a reason.
	Dismiss(ctx context.Context, id uuid.UUID, dismissedBy, reason string) (correlation.Correlation, error)
	// SetInvestigation records the Phase 9 investigation this correlation
	// was attached to (phase12.md §35).
	SetInvestigation(ctx context.Context, id uuid.UUID, investigationID uuid.UUID) (correlation.Correlation, error)
	// MarkMergedInto sets id's MergedIntoID — id's own row, evidence, and
	// history are preserved unmodified otherwise (phase12.md §29).
	MarkMergedInto(ctx context.Context, id uuid.UUID, survivorID uuid.UUID) (correlation.Correlation, error)
	// AppendMergedFrom appends mergedIDs to survivorID's MergedFromIDs
	// (phase12.md §29's "preserve original correlation IDs").
	AppendMergedFrom(ctx context.Context, survivorID uuid.UUID, mergedIDs []uuid.UUID) (correlation.Correlation, error)
}

// NodeRepository persists and queries Node rows (which also
// serve as this platform's CorrelationEvidence rows — see
// internal/domain/correlation.Node's doc comment).
type NodeRepository interface {
	// CreateNode inserts n, or is a deduplicating no-op if a node with
	// the same (correlation_id, type, reference_id) already exists.
	CreateNode(ctx context.Context, n correlation.Node) (result correlation.Node, created bool, err error)
	ListNodes(ctx context.Context, correlationID uuid.UUID) ([]correlation.Node, error)
	// ReassignNodes moves the given node IDs onto a different
	// correlation — used by Split (phase12.md §30) to divide an existing
	// correlation's evidence between the original and a newly created
	// row without deleting any node.
	ReassignNodes(ctx context.Context, nodeIDs []uuid.UUID, newCorrelationID uuid.UUID) error
}

// EdgeRepository persists and queries Edge rows.
type EdgeRepository interface {
	// CreateEdge inserts e, or is a deduplicating no-op if an edge with
	// the same (correlation_id, source_node_id, target_node_id,
	// relationship, strategy_id) already exists.
	CreateEdge(ctx context.Context, e correlation.Edge) (result correlation.Edge, created bool, err error)
	ListEdges(ctx context.Context, correlationID uuid.UUID) ([]correlation.Edge, error)
	// EdgesTouching returns every edge referencing any of nodeIDs as
	// either endpoint — used by Split to carry the right edges over to
	// the new correlation along with its reassigned nodes.
	EdgesTouching(ctx context.Context, nodeIDs []uuid.UUID) ([]correlation.Edge, error)
	// ReassignEdges moves the given edge IDs onto a different
	// correlation (see ReassignNodes).
	ReassignEdges(ctx context.Context, edgeIDs []uuid.UUID, newCorrelationID uuid.UUID) error
}

// ChainRepository persists and queries AttackChain rows.
type ChainRepository interface {
	CreateChain(ctx context.Context, c correlation.AttackChain) (correlation.AttackChain, error)
	GetChainByCorrelationID(ctx context.Context, correlationID uuid.UUID) (correlation.AttackChain, error)
	GetChainByID(ctx context.Context, id uuid.UUID) (correlation.AttackChain, error)
	ListChains(ctx context.Context, pageParams pagination.Params) (pagination.Page[correlation.AttackChain], error)
	UpdateChainStatus(ctx context.Context, id uuid.UUID, status correlation.Status) (correlation.AttackChain, error)
}

// StageRepository persists and queries AttackChainStage rows.
type StageRepository interface {
	CreateStage(ctx context.Context, s correlation.AttackChainStage) (correlation.AttackChainStage, error)
	ListStages(ctx context.Context, chainID uuid.UUID) ([]correlation.AttackChainStage, error)
}
