// Package intelligence implements persistence for the intelligence domain
// model — mirroring internal/repository/investigation's shape and
// conventions exactly (one PostgresRepository type implementing several
// narrow, entity-specific interfaces). It never imports
// internal/intelligence (the engine) — CacheRepository deals in raw bytes
// rather than intelligence.Record, so the engine/repository boundary
// internal/detection and internal/repository/finding already establish
// holds here too; internal/service/intelligence is what bridges the two.
package intelligence

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/intelligence"
	"ai-surface-platform/internal/repository/pagination"
)

// RecordListFilter narrows an intelligence record listing.
type RecordListFilter struct {
	TargetID       uuid.UUID
	IndicatorType  intelligence.IndicatorType
	IndicatorValue string
	ProviderID     string
	Pagination     pagination.Params
}

// RecordRepository persists and queries Record rows.
type RecordRepository interface {
	// UpsertRecord inserts r's row, or updates FirstSeen/LastSeen/
	// Expiration/RetrievedAt/NormalizedData/Tags if a row with the same
	// (target_id, provider_id, indicator_type, indicator_value, verdict,
	// confidence, source_reference) already exists — re-observing an
	// unchanged verdict/confidence never accumulates unbounded duplicate
	// rows, while a genuinely different observation (a changed verdict)
	// is always a new row, preserving history (phase10.md §47).
	UpsertRecord(ctx context.Context, r intelligence.Record) (result intelligence.Record, created bool, err error)
	// ListRecords returns a page of records matching filter, ordered by
	// (created_at, id).
	ListRecords(ctx context.Context, filter RecordListFilter) (pagination.Page[intelligence.Record], error)
	// ListRecordsByIndicator returns every record for one indicator
	// within targetID — bounded by the number of registered providers,
	// so no pagination is needed.
	ListRecordsByIndicator(ctx context.Context, targetID uuid.UUID, indicatorType intelligence.IndicatorType, indicatorValue string) ([]intelligence.Record, error)
}

// VulnerabilityListFilter narrows a vulnerability-record listing.
type VulnerabilityListFilter struct {
	AffectedProduct string
	Pagination      pagination.Params
}

// MatchListFilter narrows a vulnerability-match listing.
type MatchListFilter struct {
	TargetID   uuid.UUID
	AssetID    uuid.UUID
	FindingID  *uuid.UUID
	Pagination pagination.Params
}

// VulnerabilityRepository persists and queries the vulnerability catalog
// and its matches.
type VulnerabilityRepository interface {
	// UpsertVulnerabilityRecord inserts v, or updates its mutable fields
	// if a row with the same Identifier already exists.
	UpsertVulnerabilityRecord(ctx context.Context, v intelligence.VulnerabilityRecord) (result intelligence.VulnerabilityRecord, created bool, err error)
	GetVulnerabilityByIdentifier(ctx context.Context, identifier string) (intelligence.VulnerabilityRecord, error)
	ListVulnerabilityRecords(ctx context.Context, filter VulnerabilityListFilter) (pagination.Page[intelligence.VulnerabilityRecord], error)
	// UpsertVulnerabilityMatch inserts m, or updates its mutable fields
	// if a row with the same (asset_id, vulnerability_id, observed_
	// version) already exists — re-running matching over unchanged
	// evidence is idempotent, never producing duplicate matches.
	UpsertVulnerabilityMatch(ctx context.Context, m intelligence.VulnerabilityMatch) (result intelligence.VulnerabilityMatch, created bool, err error)
	ListVulnerabilityMatches(ctx context.Context, filter MatchListFilter) (pagination.Page[intelligence.VulnerabilityMatch], error)
}

// RiskRepository persists and queries RiskScore rows. A score is always
// inserted, never updated — recalculation preserves history (phase10.md
// §45/§46).
type RiskRepository interface {
	CreateRiskScore(ctx context.Context, r intelligence.RiskScore) (intelligence.RiskScore, error)
	// GetLatestRiskScore returns the most recently calculated score for
	// (entityType, entityID), or a errors.CategoryNotFound error if none
	// exists yet.
	GetLatestRiskScore(ctx context.Context, entityType intelligence.EntityType, entityID uuid.UUID) (intelligence.RiskScore, error)
	// ListRiskHistory returns every score ever calculated for
	// (entityType, entityID), newest first.
	ListRiskHistory(ctx context.Context, entityType intelligence.EntityType, entityID uuid.UUID, params pagination.Params) (pagination.Page[intelligence.RiskScore], error)
}

// EventListFilter narrows an enrichment-event listing.
type EventListFilter struct {
	TargetID       uuid.UUID
	IndicatorType  intelligence.IndicatorType
	IndicatorValue string
	Pagination     pagination.Params
}

// EventRepository persists and queries EnrichmentEvent rows.
type EventRepository interface {
	RecordEvent(ctx context.Context, e intelligence.EnrichmentEvent) (intelligence.EnrichmentEvent, error)
	ListEvents(ctx context.Context, filter EventListFilter) (pagination.Page[intelligence.EnrichmentEvent], error)
}

// CriticalityRepository persists and queries AssetCriticality rows.
type CriticalityRepository interface {
	// SetCriticality inserts or replaces the criticality row for
	// a.AssetID (an explicit analyst action always wins over any prior
	// value — phase10.md §36).
	SetCriticality(ctx context.Context, a intelligence.AssetCriticality) (intelligence.AssetCriticality, error)
	// GetCriticality returns assetID's criticality, or
	// intelligence.CriticalityNormal (never persisted, never an error)
	// if none has ever been explicitly set — "normal" is the honest
	// default absent any analyst input.
	GetCriticality(ctx context.Context, assetID uuid.UUID) (intelligence.AssetCriticality, bool, error)
}

// CacheRepository persists provider lookup results for
// internal/service/intelligence to wrap as an internal/intelligence.
// Cache implementation (phase10.md §23). It deals only in raw bytes
// (JSON-encoded by the caller) — see package doc comment for why.
type CacheRepository interface {
	GetCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string) (data []byte, expiresAt *time.Time, found bool, err error)
	SetCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string, data []byte, expiresAt *time.Time) error
	InvalidateCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string) error
}
