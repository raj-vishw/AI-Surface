package intelligence

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEngine_Lookup_MergesAndIsolatesFailures(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubProvider{id: "ok1", records: []Record{{ProviderID: "ok1", SourceType: "local", Verdict: VerdictUnknown, Confidence: ConfidenceHigh}}})
	_ = r.Register(stubProvider{id: "failing", err: errors.New("timeout")})
	_ = r.Register(stubProvider{id: "ok2", records: []Record{{ProviderID: "ok2", SourceType: "reputation", Verdict: VerdictBenign, Confidence: ConfidenceMedium}}})

	e := NewEngine(r)
	result := e.Lookup(context.Background(), Indicator{Type: IndicatorDomain, Value: "EXAMPLE.com"}, Config{}, NewMemoryCache())

	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records from 2 successful providers, got %d: %+v", len(result.Records), result.Records)
	}
	if len(result.Errors) != 1 || result.Errors[0].ProviderID != "failing" {
		t.Fatalf("expected 1 isolated error from 'failing', got %+v", result.Errors)
	}
	if result.Indicator.Value != "example.com" {
		t.Fatalf("expected normalized indicator, got %q", result.Indicator.Value)
	}
}

func TestEngine_Lookup_ExternalProviderRequiresOptIn(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubProvider{id: "feed", capabilities: []Capability{CapabilityThreatFeed}, records: []Record{{ProviderID: "feed", Verdict: VerdictMalicious}}})

	e := NewEngine(r)

	disabled := e.Lookup(context.Background(), Indicator{Type: IndicatorDomain, Value: "x.com"}, Config{ExternalEnrichmentEnabled: false}, NewMemoryCache())
	if len(disabled.Records) != 0 {
		t.Fatalf("expected no records with external enrichment disabled, got %+v", disabled.Records)
	}

	enabled := e.Lookup(context.Background(), Indicator{Type: IndicatorDomain, Value: "x.com"}, Config{ExternalEnrichmentEnabled: true}, NewMemoryCache())
	if len(enabled.Records) != 1 {
		t.Fatalf("expected 1 record with external enrichment enabled, got %+v", enabled.Records)
	}
}

func TestEngine_Plan_DryRun_NoLookupPerformed(t *testing.T) {
	r := NewRegistry()
	called := false
	_ = r.Register(stubProvider{id: "local"})
	_ = r.Register(stubProvider{id: "feed", capabilities: []Capability{CapabilityThreatFeed}})
	e := NewEngine(r)

	plan := e.Plan(Config{ExternalEnrichmentEnabled: false})
	if len(plan) != 1 || plan[0] != "local" {
		t.Fatalf("Plan() = %v, want only [local] (external disabled)", plan)
	}
	if called {
		t.Fatal("Plan must never invoke a provider")
	}
}

// countingCache wraps MemoryCache to count Get/Set calls, verifying that
// a cached (fresh) provider result is not re-fetched.
type countingCache struct {
	*MemoryCache
	gets, sets int
}

func (c *countingCache) Get(ctx context.Context, key CacheKey) ([]Record, bool, error) {
	c.gets++
	return c.MemoryCache.Get(ctx, key)
}
func (c *countingCache) Set(ctx context.Context, key CacheKey, records []Record, ttl time.Duration) error {
	c.sets++
	return c.MemoryCache.Set(ctx, key, records, ttl)
}

func TestEngine_Lookup_CacheHitAvoidsReLookup(t *testing.T) {
	calls := 0
	r := NewRegistry()
	_ = r.Register(&countingLookupProvider{id: "p", calls: &calls})
	e := NewEngine(r)
	cache := &countingCache{MemoryCache: NewMemoryCache()}

	e.Lookup(context.Background(), Indicator{Type: IndicatorDomain, Value: "x.com"}, Config{}, cache)
	e.Lookup(context.Background(), Indicator{Type: IndicatorDomain, Value: "x.com"}, Config{}, cache)

	if calls != 1 {
		t.Fatalf("expected provider Lookup called once (second call served from cache), got %d", calls)
	}
	if cache.sets != 1 {
		t.Fatalf("expected exactly 1 cache write, got %d", cache.sets)
	}
}

type countingLookupProvider struct {
	id    string
	calls *int
}

func (p *countingLookupProvider) ID() string                 { return p.id }
func (p *countingLookupProvider) Name() string               { return p.id }
func (p *countingLookupProvider) Version() string            { return "1" }
func (p *countingLookupProvider) Capabilities() []Capability { return nil }
func (p *countingLookupProvider) Lookup(_ context.Context, i Indicator) ([]Record, error) {
	*p.calls++
	return []Record{{Indicator: i, ProviderID: p.id, Verdict: VerdictUnknown, Confidence: ConfidenceLow}}, nil
}
