// Package endpoint implements persistence for the endpoint domain model.
package endpoint

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/endpoint"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows an endpoint listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	AssetID        uuid.UUID
	Status         endpoint.Status
	Classification endpoint.Classification
	ScanID         *uuid.UUID
	MinConfidence  float64
	Pagination     pagination.Params
}

// Repository persists and queries Endpoint rows.
type Repository interface {
	// Upsert inserts e's row if no endpoint with its (AssetID, Method,
	// normalized URL) exists yet, or merges a new observation into the
	// existing row if one does: LastSeen advances to the later of the two
	// timestamps, FirstSeen moves to the earlier of the two (so it always
	// ends up as the true earliest observation regardless of the order
	// concurrent callers' upserts happen to reach the database in —
	// see asset.Repository.Upsert's doc comment for why "earlier" rather
	// than "never touched" is the correct rule here), ContentType/
	// StatusCode/ResponseHash/QueryPattern/ContentLength/APIType/
	// APIVersion/Classification update to the latest non-empty
	// observation, Sources accumulates as a deduplicated union (never
	// shrinks — phase7.md §40), Confidence takes the higher of the two
	// (corroboration never lowers it), Documented/Observed/Inferred are
	// monotonic OR (once true from any run, stays true), and Metadata is
	// shallow-merged. Status is preserved — the same explicit-status-
	// change discipline as asset.Repository. created reports whether a
	// new row was inserted.
	Upsert(ctx context.Context, e endpoint.Endpoint) (result endpoint.Endpoint, created bool, err error)
	// GetByID returns the endpoint with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (endpoint.Endpoint, error)
	// ListByAsset returns a page of endpoints for filter.AssetID, ordered
	// by (created_at, id).
	ListByAsset(ctx context.Context, filter ListFilter) (pagination.Page[endpoint.Endpoint], error)
	// UpdateStatus explicitly sets an endpoint's lifecycle status — the
	// only way an endpoint's Status changes, mirroring
	// asset.Repository.UpdateStatus (phase7.md §43/§45: a status change,
	// e.g. moving to INACTIVE when an endpoint is no longer discoverable,
	// is never implicit).
	UpdateStatus(ctx context.Context, id uuid.UUID, status endpoint.Status) (endpoint.Endpoint, error)
	// MarkInactiveExcept sets status = INACTIVE for every non-INACTIVE
	// endpoint belonging to assetID whose id is not in stillFound — the
	// "removed" half of change detection (phase7.md §43: preserved, never
	// deleted). Returns the endpoints that were transitioned.
	MarkInactiveExcept(ctx context.Context, assetID uuid.UUID, stillFound []uuid.UUID) ([]endpoint.Endpoint, error)
}

// ParameterInput describes one observed parameter name for an endpoint —
// never a value (phase7.md §9/§37).
type ParameterInput struct {
	EndpointID uuid.UUID
	Name       string
	Location   string // "query", "path", "form"
	ObservedAt time.Time
}

// Parameter is a persisted endpoint parameter observation.
type Parameter struct {
	ID         uuid.UUID
	EndpointID uuid.UUID
	Name       string
	Location   string
	FirstSeen  time.Time
	LastSeen   time.Time
	CreatedAt  time.Time
}

// ParameterRepository persists and queries endpoint parameter names.
// Named distinctly from Repository (UpsertParameter, not Upsert) because
// PostgresRepository implements both on one type.
type ParameterRepository interface {
	// UpsertParameter records name/location as observed for
	// input.EndpointID, creating the row on first observation or
	// advancing LastSeen on a repeat one. Never stores a value.
	UpsertParameter(ctx context.Context, input ParameterInput) (Parameter, bool, error)
	// ListParameters returns every parameter observed for endpointID.
	ListParameters(ctx context.Context, endpointID uuid.UUID) ([]Parameter, error)
}

// EvidenceListFilter narrows an evidence listing.
type EvidenceListFilter struct {
	EndpointID uuid.UUID
	Pagination pagination.Params
}

// EvidenceRepository persists and queries append-only endpoint_evidence
// rows — named distinctly from Repository (CreateEvidence, not Create)
// because PostgresRepository implements both on one type, mirroring
// internal/repository/asset's EvidenceRepository exactly.
type EvidenceRepository interface {
	// CreateEvidence inserts e. If an evidence row with the same
	// (endpoint_id, source, evidence_fingerprint) already exists, the
	// insert is a deduplicating no-op: the existing row is returned
	// unchanged and created is false.
	CreateEvidence(ctx context.Context, e endpoint.Evidence) (result endpoint.Evidence, created bool, err error)
	// ListEvidenceByEndpoint returns a page of evidence for
	// filter.EndpointID, ordered by (created_at, id).
	ListEvidenceByEndpoint(ctx context.Context, filter EvidenceListFilter) (pagination.Page[endpoint.Evidence], error)
}
