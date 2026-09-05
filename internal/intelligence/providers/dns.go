package providers

import (
	"context"
	"time"

	"ai-recon-platform/internal/intelligence"
)

const dnsProviderVersion = "1"

// DNSProvider surfaces already-persisted DNS observations (Phase 5) for
// a domain/subdomain/hostname indicator (phase10.md §8). It performs no
// DNS query of its own — "use existing DNS observations", never
// unrestricted enumeration (phase10.md §8).
type DNSProvider struct {
	source *DatasetSource
}

// NewDNSProvider builds a DNSProvider reading from source.
func NewDNSProvider(source *DatasetSource) *DNSProvider {
	return &DNSProvider{source: source}
}

// ID implements intelligence.Provider.
func (p *DNSProvider) ID() string { return "dns" }

// Name implements intelligence.Provider.
func (p *DNSProvider) Name() string { return "DNS Enrichment" }

// Version implements intelligence.Provider.
func (p *DNSProvider) Version() string { return dnsProviderVersion }

// Capabilities implements intelligence.Provider.
func (p *DNSProvider) Capabilities() []intelligence.Capability {
	return []intelligence.Capability{intelligence.CapabilityDNS}
}

// Lookup applies only to domain/subdomain/hostname indicators; any other
// type returns no records.
func (p *DNSProvider) Lookup(_ context.Context, indicator intelligence.Indicator) ([]intelligence.Record, error) {
	switch indicator.Type {
	case intelligence.IndicatorDomain, intelligence.IndicatorSubdomain, intelligence.IndicatorHostname:
	default:
		return nil, nil
	}

	records, ok := p.source.Get().DNSRecords[indicator.Value]
	if !ok || len(records) == 0 {
		return nil, nil
	}

	byType := map[string][]string{}
	for _, r := range records {
		byType[r.Type] = append(byType[r.Type], r.Value)
	}
	normalized := map[string]any{}
	for t, values := range byType {
		normalized[t] = values
	}

	return []intelligence.Record{{
		Indicator: indicator, SourceType: "dns",
		Verdict: intelligence.VerdictUnknown, Confidence: intelligence.ConfidenceHigh,
		RetrievedAt:    time.Now().UTC(),
		NormalizedData: normalized,
	}}, nil
}
