// Package providers implements internal/intelligence.Provider
// implementations. Local/DNS/Certificate/Technology operate entirely on a
// LocalDataset snapshot assembled by internal/service/intelligence from
// already-persisted Phase 2-8 data (asset metadata, fingerprints,
// findings) — mirroring internal/detection's "Input built entirely from
// already-persisted data by the service layer, never fetched by the
// component itself" discipline (phase8.md §1/phase10.md §7). ThreatFeed
// is the one external, network-backed, opt-in provider (phase10.md §29/
// §30) — see threat_feed.go.
//
// Every local-data provider deliberately reports Verdict ==
// intelligence.VerdictUnknown: this platform has no external reputation
// database of its own, and inferring "malicious"/"suspicious" from local
// observations alone (a changed DNS record, an expired certificate) would
// be exactly the unsupported threat-attribution phase10.md §101
// prohibits. They still return rich NormalizedData/Tags describing what
// was actually observed — descriptive context, not a verdict judgment
// (phase10.md §98).
package providers

import (
	"context"
	"sync"
	"time"

	"ai-surface-platform/internal/intelligence"
)

// DNSRecordObservation is one already-persisted DNS record (Phase 5) for
// a domain/subdomain/hostname indicator.
type DNSRecordObservation struct {
	Type  string // A, AAAA, CNAME, MX, NS, TXT, SOA, CAA
	Value string
}

// CertificateObservation is already-persisted TLS/certificate metadata
// (Phase 4/8's TLSObservation) for a host indicator.
type CertificateObservation struct {
	Host               string
	Issuer             string
	Subject            string
	SANs               []string
	NotAfter           time.Time
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
}

// TechnologyObservation is one already-persisted technology fingerprint
// (Phase 6) for a host/asset indicator.
type TechnologyObservation struct {
	Product    string
	Vendor     string
	Version    string
	Category   string
	Confidence float64
}

// AssetHistoryObservation summarizes an indicator's known history in the
// platform's own inventory — used to populate the local provider's
// "asset history" signal (phase10.md §7).
type AssetHistoryObservation struct {
	FirstSeen       time.Time
	LastSeen        time.Time
	FindingCount    int
	RecentlyChanged bool // true if any observed property changed within the recency window the service layer applied
}

// LocalDataset is the in-memory snapshot Local/DNS/Certificate/
// Technology providers look up against — one dataset assembled per
// enrichment run by internal/service/intelligence, keyed by the exact
// normalized indicator value the corresponding record concerns.
type LocalDataset struct {
	DNSRecords   map[string][]DNSRecordObservation
	Certificates map[string]CertificateObservation
	Technologies map[string][]TechnologyObservation
	AssetHistory map[string]AssetHistoryObservation
}

// NewLocalDataset builds an empty LocalDataset.
func NewLocalDataset() LocalDataset {
	return LocalDataset{
		DNSRecords:   map[string][]DNSRecordObservation{},
		Certificates: map[string]CertificateObservation{},
		Technologies: map[string][]TechnologyObservation{},
		AssetHistory: map[string]AssetHistoryObservation{},
	}
}

// DatasetSource holds the LocalDataset every Local/DNS/Certificate/
// Technology provider reads from. It is mutable and shared (a pointer),
// not a value baked into each provider at construction time: one
// long-lived Registry/Engine pair is built once per process, but the
// dataset it should look up against changes with every asset/indicator
// internal/service/intelligence enriches. Callers must call Set before
// each Engine.Lookup that depends on local data — the same "caller
// assembles the input, the provider never fetches its own" discipline
// phase8.md §1 establishes, just with an update step instead of a
// constructor argument because one process handles many lookups.
//
// This is safe for the CLI's single-invocation-per-process model — every
// Engine.Lookup call in this codebase runs its providers sequentially,
// never concurrently with a different Set call — but is NOT safe for a
// hypothetical concurrent server handling multiple enrichments at once
// without per-request isolation; see docs/architecture/threat-
// intelligence.md's Known Limitations.
type DatasetSource struct {
	mu      sync.RWMutex
	dataset LocalDataset
}

// NewDatasetSource builds a DatasetSource holding an empty dataset.
func NewDatasetSource() *DatasetSource {
	return &DatasetSource{dataset: NewLocalDataset()}
}

// Set replaces the dataset every provider reads from.
func (s *DatasetSource) Set(ds LocalDataset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataset = ds
}

// Get returns the current dataset.
func (s *DatasetSource) Get() LocalDataset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dataset
}

const localProviderVersion = "1"

// LocalProvider surfaces already-persisted platform data as intelligence
// records, requiring no external service (phase10.md §7) — this makes
// Phase 10 useful even with every external provider disabled.
type LocalProvider struct {
	source *DatasetSource
}

// NewLocalProvider builds a LocalProvider reading from source.
func NewLocalProvider(source *DatasetSource) *LocalProvider {
	return &LocalProvider{source: source}
}

// ID implements intelligence.Provider.
func (p *LocalProvider) ID() string { return "local" }

// Name implements intelligence.Provider.
func (p *LocalProvider) Name() string { return "Local Platform Data" }

// Version implements intelligence.Provider.
func (p *LocalProvider) Version() string { return localProviderVersion }

// Capabilities implements intelligence.Provider.
func (p *LocalProvider) Capabilities() []intelligence.Capability {
	return []intelligence.Capability{intelligence.CapabilityLocal}
}

// Lookup returns a descriptive record for indicator if this platform has
// any history for it, or an empty slice (never an error) if it doesn't —
// "nothing known locally" is a normal, common outcome, not a failure.
func (p *LocalProvider) Lookup(_ context.Context, indicator intelligence.Indicator) ([]intelligence.Record, error) {
	dataset := p.source.Get()
	hist, ok := dataset.AssetHistory[indicator.Value]
	if !ok {
		return nil, nil
	}

	tags := []string{}
	if hist.RecentlyChanged {
		tags = append(tags, "recently-changed")
	}
	if hist.FindingCount > 0 {
		tags = append(tags, "has-open-findings")
	}

	now := time.Now().UTC()
	return []intelligence.Record{{
		Indicator: indicator, SourceType: "local",
		Verdict: intelligence.VerdictUnknown, Confidence: intelligence.ConfidenceHigh,
		FirstSeen: hist.FirstSeen, LastSeen: hist.LastSeen, RetrievedAt: now,
		NormalizedData: map[string]any{
			"first_seen":       hist.FirstSeen,
			"last_seen":        hist.LastSeen,
			"finding_count":    hist.FindingCount,
			"recently_changed": hist.RecentlyChanged,
		},
		Tags: tags,
	}}, nil
}
