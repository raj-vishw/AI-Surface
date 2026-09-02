// Package fingerprint implements persistence for the fingerprint and
// fingerprint-evidence domain models — mirroring
// internal/repository/asset's shape and conventions exactly (phase6.md
// §21/§47).
package fingerprint

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/fingerprint"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows a fingerprint listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	AssetID        uuid.UUID
	TargetID       uuid.UUID
	Category       fingerprint.Category
	Technology     string
	Status         fingerprint.Status
	MinConfidence  float64
	ScanID         *uuid.UUID
	FirstSeenAfter time.Time
	LastSeenAfter  time.Time
	Pagination     pagination.Params
}

// Repository persists and queries Fingerprint rows.
type Repository interface {
	// GetByID returns the fingerprint with the given id, or a
	// errors.CategoryNotFound error if none exists.
	GetByID(ctx context.Context, id uuid.UUID) (fingerprint.Fingerprint, error)
	// List returns a page of fingerprints matching filter, ordered by
	// (created_at, id).
	List(ctx context.Context, filter ListFilter) (pagination.Page[fingerprint.Fingerprint], error)
	// Upsert inserts f's row if no fingerprint with its (AssetID,
	// IdentityKey) exists yet, or merges a new observation into the
	// existing row otherwise: LastSeen advances to the later of the two
	// timestamps, FirstSeen takes the earlier (the same MIN/MAX upsert
	// discipline internal/repository/asset.Upsert documents, for the
	// identical out-of-order-observation reason), Confidence/Version/
	// Vendor/Product/ScanID/Metadata take the new observation's values
	// (a fingerprint's "current belief" should reflect the most recent
	// analysis, unlike Asset's confidence-max/metadata-merge — see
	// postgres.go's doc comment), and Status is always forced to ACTIVE
	// (a fingerprint being upserted was, by definition, just re-matched).
	// created reports whether a new row was inserted.
	Upsert(ctx context.Context, f fingerprint.Fingerprint) (result fingerprint.Fingerprint, created bool, err error)
	// MarkInactive sets status = INACTIVE for every ACTIVE fingerprint
	// belonging to assetID whose id is not in stillMatched — the
	// "removed" half of change detection (phase6.md §22/§23): a
	// fingerprint that no longer matches is preserved, never deleted.
	// Returns the fingerprints that were transitioned.
	MarkInactive(ctx context.Context, assetID uuid.UUID, stillMatched []uuid.UUID) ([]fingerprint.Fingerprint, error)
}

// EvidenceListFilter narrows an evidence listing.
type EvidenceListFilter struct {
	FingerprintID uuid.UUID
	Pagination    pagination.Params
}

// EvidenceRepository persists and queries append-only
// fingerprint_evidence rows. Named distinctly from Repository (
// CreateEvidence, not Create) because PostgresRepository implements both
// on one type, mirroring internal/repository/asset's EvidenceRepository.
type EvidenceRepository interface {
	// CreateEvidence inserts e. If an evidence row with the same
	// (fingerprint_id, signals_fingerprint) already exists, the insert is
	// a deduplicating no-op: the existing row is returned unchanged and
	// created is false.
	CreateEvidence(ctx context.Context, e fingerprint.Evidence) (result fingerprint.Evidence, created bool, err error)
	// ListEvidenceByFingerprint returns a page of evidence for
	// fingerprintID, ordered by (created_at, id).
	ListEvidenceByFingerprint(ctx context.Context, filter EvidenceListFilter) (pagination.Page[fingerprint.Evidence], error)
}
