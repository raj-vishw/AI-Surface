package intelligence

import (
	"context"
	"time"
)

// LookupResult is one Engine.Lookup call's outcome.
type LookupResult struct {
	Indicator Indicator
	Records   []Record
	Errors    []ProviderError
	// CacheHits names the providers whose result was served from cache
	// rather than a fresh Lookup call.
	CacheHits []string
}

// Engine runs a Registry's active, config-enabled providers against one
// Indicator and merges their output. It performs no persistence of its
// own — see internal/service/intelligence for that. A Cache is required
// (use NewMemoryCache for a no-op default) so external provider results
// aren't fetched more often than their TTL requires (phase10.md §23).
type Engine struct {
	registry *Registry
}

// NewEngine builds an Engine backed by registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// isExternal reports whether p is a threat-feed (external, opt-in)
// provider (phase10.md §29/§30).
func isExternal(p Provider) bool {
	for _, c := range p.Capabilities() {
		if c == CapabilityThreatFeed {
			return true
		}
	}
	return false
}

// Plan returns the provider ids that Lookup would actually query under
// cfg — used by --dry-run to report "0 external requests" without
// performing any lookup (phase10.md §72). It takes no Indicator: every
// current policy decision (provider enabled, external-enrichment opt-in)
// is indicator-independent, so the plan is the same for every indicator
// under a given cfg.
func (e *Engine) Plan(cfg Config) []string {
	var ids []string
	for _, p := range e.registry.Active() {
		if !cfg.ProviderEnabled(p.ID()) {
			continue
		}
		if isExternal(p) && !cfg.ExternalEnrichmentEnabled {
			continue
		}
		ids = append(ids, p.ID())
	}
	return ids
}

// ttlFor returns the cache TTL to apply to a provider's results, based on
// its dominant capability (phase10.md §22's reputation/vulnerability
// worked example).
func ttlFor(p Provider, cfg Config) time.Duration {
	for _, c := range p.Capabilities() {
		if c == CapabilityVulnerability {
			return cfg.EffectiveVulnerabilityTTL()
		}
	}
	return cfg.EffectiveReputationTTL()
}

// Lookup queries every active, config-enabled, policy-permitted provider
// for indicator, isolating each provider's failure (phase10.md §25),
// serving cached results within TTL instead of re-querying (phase10.md
// §23), and deduplicating the merged result (phase10.md §78/dedup.go)
// before returning. indicator is normalized before use.
func (e *Engine) Lookup(ctx context.Context, indicator Indicator, cfg Config, cache Cache) LookupResult {
	indicator = Normalize(indicator)
	result := LookupResult{Indicator: indicator}
	if cache == nil {
		cache = NewMemoryCache()
	}

	for _, p := range e.registry.Active() {
		if !cfg.ProviderEnabled(p.ID()) {
			continue
		}
		if isExternal(p) && !cfg.ExternalEnrichmentEnabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, ProviderError{ProviderID: p.ID(), Err: err})
			break
		}

		key := CacheKey{ProviderID: p.ID(), Indicator: indicator}
		if cached, ok, err := cache.Get(ctx, key); err == nil && ok {
			fresh := FreshRecords(cached, time.Now())
			if len(fresh) > 0 {
				result.Records = append(result.Records, fresh...)
				result.CacheHits = append(result.CacheHits, p.ID())
				continue
			}
		}

		providerCtx, cancel := context.WithTimeout(ctx, cfg.EffectiveProviderTimeout())
		start := time.Now()
		records, err := p.Lookup(providerCtx, indicator)
		cancel()
		if err != nil {
			e.registry.RecordFailure(p.ID(), err)
			result.Errors = append(result.Errors, ProviderError{ProviderID: p.ID(), Err: err})
			continue
		}
		e.registry.RecordSuccess(p.ID(), time.Since(start))

		for i := range records {
			if records[i].ProviderID == "" {
				records[i].ProviderID = p.ID()
			}
			if records[i].ProviderVersion == "" {
				records[i].ProviderVersion = p.Version()
			}
			if records[i].RetrievedAt.IsZero() {
				records[i].RetrievedAt = time.Now().UTC()
			}
		}
		if err := cache.Set(ctx, key, records, ttlFor(p, cfg)); err != nil {
			// Cache write failure never fails the lookup itself — the
			// records were still obtained successfully.
			result.Errors = append(result.Errors, ProviderError{ProviderID: p.ID(), Err: err})
		}
		result.Records = append(result.Records, records...)
	}

	result.Records = DedupRecords(result.Records)
	return result
}
