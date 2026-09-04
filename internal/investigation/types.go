// Package investigation implements Phase 9's correlation engine: a
// self-contained set of Rules that analyze an investigation's attached
// findings (plus their sibling assets/endpoints/technology fingerprints)
// and produce explainable Relationship candidates. Mirroring
// internal/detection's split (phase8.md §1, reused verbatim for phase9.md
// §1), this package has no database dependency — it takes an in-memory
// Input built entirely from already-persisted data and returns in-memory
// Relationship values; internal/service/investigation is the bridge that
// assembles Input, calls Engine.Correlate, and persists the result.
//
// The correlation engine never claims a relationship is definitely true —
// every Relationship carries an Explanation and the individual Signals
// that produced its Score (phase9.md §35/§38), and Status distinguishes
// an automatically-confirmed relationship (score >= threshold) from a
// sub-threshold candidate still surfaced for analyst review (phase9.md
// §37).
package investigation

import (
	"time"

	"github.com/google/uuid"
)

// FindingObservation is the normalized slice of an already-persisted
// Finding (internal/domain/finding, Phase 8) a correlation rule needs.
type FindingObservation struct {
	ID         uuid.UUID
	AssetID    uuid.UUID
	EndpointID *uuid.UUID
	DetectorID string
	Category   string
	Severity   string
	ScanID     *uuid.UUID
	FirstSeen  time.Time
	LastSeen   time.Time
}

// AssetObservation is the normalized slice of an already-persisted Asset
// (internal/domain/asset, Phase 2) a correlation rule needs.
type AssetObservation struct {
	ID        uuid.UUID
	Hostname  string
	IP        string
	Type      string
	FirstSeen time.Time
	LastSeen  time.Time
}

// EndpointObservation is the normalized slice of an already-persisted
// Endpoint (internal/domain/endpoint, Phase 7) a correlation rule needs.
type EndpointObservation struct {
	ID        uuid.UUID
	AssetID   uuid.UUID
	Path      string
	FirstSeen time.Time
	LastSeen  time.Time
}

// TechnologyObservation is one already-persisted technology belief
// (internal/domain/fingerprint, Phase 6) for an asset.
type TechnologyObservation struct {
	ID         uuid.UUID
	AssetID    uuid.UUID
	Category   string
	Technology string
	Version    string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Input bundles everything one correlation pass over an investigation's
// attached findings consumes — built entirely from already-persisted
// Phase 2/6/7/8 data by internal/service/investigation, never assembled
// by a Rule itself.
type Input struct {
	Findings     []FindingObservation
	Assets       map[uuid.UUID]AssetObservation
	Endpoints    map[uuid.UUID]EndpointObservation
	Technologies []TechnologyObservation

	Config Config
}

// AssetOf returns the AssetObservation for assetID, or the zero value and
// false if unknown.
func (in Input) AssetOf(assetID uuid.UUID) (AssetObservation, bool) {
	a, ok := in.Assets[assetID]
	return a, ok
}

// EndpointOf returns the EndpointObservation for endpointID, or the zero
// value and false if unknown.
func (in Input) EndpointOf(endpointID uuid.UUID) (EndpointObservation, bool) {
	e, ok := in.Endpoints[endpointID]
	return e, ok
}
