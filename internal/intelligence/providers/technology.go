package providers

import (
	"context"
	"time"

	"ai-surface-platform/internal/intelligence"
)

const technologyProviderVersion = "1"

// TechnologyProvider surfaces already-persisted technology fingerprints
// (Phase 6) for a host/asset indicator, normalized to product/vendor/
// version/category (phase10.md §11). It never invents a version — an
// observation with no version evidence is returned with Version == ""
// (phase10.md §11).
type TechnologyProvider struct {
	source *DatasetSource
}

// NewTechnologyProvider builds a TechnologyProvider reading from source.
func NewTechnologyProvider(source *DatasetSource) *TechnologyProvider {
	return &TechnologyProvider{source: source}
}

// ID implements intelligence.Provider.
func (p *TechnologyProvider) ID() string { return "technology" }

// Name implements intelligence.Provider.
func (p *TechnologyProvider) Name() string { return "Technology Enrichment" }

// Version implements intelligence.Provider.
func (p *TechnologyProvider) Version() string { return technologyProviderVersion }

// Capabilities implements intelligence.Provider.
func (p *TechnologyProvider) Capabilities() []intelligence.Capability {
	return []intelligence.Capability{intelligence.CapabilityTechnology}
}

// Lookup implements intelligence.Provider.
func (p *TechnologyProvider) Lookup(_ context.Context, indicator intelligence.Indicator) ([]intelligence.Record, error) {
	techs, ok := p.source.Get().Technologies[indicator.Value]
	if !ok || len(techs) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	out := make([]intelligence.Record, 0, len(techs))
	for _, t := range techs {
		out = append(out, intelligence.Record{
			Indicator: indicator, SourceType: "technology",
			Verdict: intelligence.VerdictUnknown, Confidence: confidenceFromFloat(t.Confidence),
			RetrievedAt: now,
			NormalizedData: map[string]any{
				"product":  t.Product,
				"vendor":   t.Vendor,
				"version":  t.Version,
				"category": t.Category,
			},
		})
	}
	return out, nil
}

// confidenceFromFloat buckets a Phase 6 fingerprint's [0,1] Score into a
// leveled intelligence.Confidence, using the same boundaries
// internal/domain/fingerprint.Score.Level applies.
func confidenceFromFloat(score float64) intelligence.Confidence {
	switch {
	case score >= 0.80:
		return intelligence.ConfidenceHigh
	case score >= 0.30:
		return intelligence.ConfidenceMedium
	case score > 0:
		return intelligence.ConfidenceLow
	default:
		return intelligence.ConfidenceUnknown
	}
}
