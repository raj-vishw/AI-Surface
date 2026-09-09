// Package asset implements persistence for the asset and asset-evidence
// domain models.
package asset

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/asset"
	"ai-surface-platform/internal/repository/pagination"
)

// ListFilter narrows an asset listing. Zero-valued fields are not applied.
type ListFilter struct {
	TargetID        uuid.UUID
	OrganizationID  *uuid.UUID
	Type            asset.Type
	Hostname        string
	IP              string
	Status          asset.Status
	Source          string
	Provider        string
	Model           string
	FirstSeenAfter  time.Time
	FirstSeenBefore time.Time
	LastSeenAfter   time.Time
	LastSeenBefore  time.Time
	Pagination      pagination.Params
}

// Repository persists and queries Asset rows.
type Repository interface {
	// Create inserts a new asset. Callers normally use Upsert instead;
	// Create is exposed for cases (tests, migrations of external data)
	// that need to bypass upsert semantics.
	Create(ctx context.Context, a asset.Asset) (asset.Asset, error)
	// GetByID returns the asset with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (asset.Asset, error)
	// GetByIdentity returns the asset within targetID whose identity_key
	// matches identityKey, or a errors.CategoryNotFound error if none
	// exists.
	GetByIdentity(ctx context.Context, targetID uuid.UUID, identityKey string) (asset.Asset, error)
	// List returns a page of assets matching filter, ordered by
	// (created_at, id).
	List(ctx context.Context, filter ListFilter) (pagination.Page[asset.Asset], error)
	// Update persists changes to an existing asset's mutable fields and
	// refreshes UpdatedAt. It does not change FirstSeen and does not
	// implement upsert-by-identity matching — see Upsert.
	Update(ctx context.Context, a asset.Asset) (asset.Asset, error)
	// Upsert inserts a's row if no asset with its (TargetID, IdentityKey)
	// exists yet, or merges a new observation into the existing row if one
	// does: LastSeen advances to the later of the two timestamps and
	// FirstSeen moves to the earlier of the two — not "never touched": two
	// concurrent callers observing the same identity can reach the
	// database in either order (see phase2.md §39's concurrency
	// requirement), so the only way FirstSeen reliably ends up as the true
	// earliest observation is to take MIN(existing, new) on every upsert,
	// exactly as LastSeen takes MAX(existing, new). Optional fields fill
	// in where the existing row has none, Confidence takes the higher of
	// the two values, and Metadata is shallow-merged (a's keys win on
	// conflict). Status and Source are never overwritten by Upsert —
	// Status changes go through UpdateStatus, and the asset's original
	// discovery Source is preserved (individual observation sources are
	// what asset_evidence records). created reports whether a new row was
	// inserted.
	Upsert(ctx context.Context, a asset.Asset) (result asset.Asset, created bool, err error)
	// UpdateStatus explicitly sets an asset's lifecycle status. This is
	// the only way an asset's Status changes — see asset.Status's
	// documentation on why upsert never does this implicitly.
	UpdateStatus(ctx context.Context, id uuid.UUID, status asset.Status) (asset.Asset, error)
	// Retire marks an asset RETIRED. It is a soft delete: the row and its
	// evidence remain in the database. See EvidenceRepository — evidence
	// is never removed by Retire.
	Retire(ctx context.Context, id uuid.UUID) (asset.Asset, error)
}

// EvidenceListFilter narrows an evidence listing.
type EvidenceListFilter struct {
	AssetID    uuid.UUID
	Source     string
	Pagination pagination.Params
}

// EvidenceRepository persists and queries append-only AssetEvidence rows.
// Its methods are named distinctly from Repository's (CreateEvidence, not
// Create) because PostgresRepository implements both interfaces on one
// type and Go does not support overloading.
type EvidenceRepository interface {
	// CreateEvidence inserts e. If an evidence row with the same
	// (asset_id, source, evidence_type, evidence_fingerprint) already
	// exists, the insert is a deduplicating no-op: the existing row is
	// returned unchanged and created is false. Evidence is otherwise
	// immutable — there is no Update.
	CreateEvidence(ctx context.Context, e asset.Evidence) (result asset.Evidence, created bool, err error)
	// ListEvidenceByAsset returns a page of evidence for assetID, ordered
	// by (created_at, id).
	ListEvidenceByAsset(ctx context.Context, filter EvidenceListFilter) (pagination.Page[asset.Evidence], error)
}
