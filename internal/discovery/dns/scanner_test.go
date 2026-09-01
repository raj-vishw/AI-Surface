package dns

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
)

func testScannerConfig() Config {
	return Config{
		Timeout:        2 * time.Second,
		MaxConcurrency: 10,
		RecordTypes:    []RecordType{TypeA},
		Subdomains:     SubdomainConfig{MaxCandidates: 100, MaxDepth: 1, WildcardDetection: true},
	}
}

func TestFilterInScope_RejectsOutOfScopeAllowsInScope(t *testing.T) {
	scope, err := discoveryhttp.NewScopeValidator("https://example.test")
	if err != nil {
		t.Fatalf("NewScopeValidator: %v", err)
	}
	candidates := []SubdomainCandidate{
		{Name: "api.example.test"},
		{Name: "evil-example.test"},      // not a subdomain of example.test (label-boundary mismatch) — must be rejected (phase5.md §78)
		{Name: "example.test.evil.test"}, // does not end in ".example.test" — must be rejected
		{Name: "dev.example.test"},
	}

	got := filterInScope(candidates, scope)

	want := map[string]bool{"api.example.test": true, "dev.example.test": true}
	if len(got) != len(want) {
		names := make([]string, len(got))
		for i, c := range got {
			names[i] = c.Name
		}
		t.Fatalf("filterInScope() = %v, want exactly %v", names, want)
	}
	for _, c := range got {
		if !want[c.Name] {
			t.Errorf("filterInScope() unexpectedly kept out-of-scope candidate %q", c.Name)
		}
	}
}

func TestFilterInScope_NilScopePassesEverythingThrough(t *testing.T) {
	candidates := []SubdomainCandidate{{Name: "api.example.test"}, {Name: "anything.else.test"}}
	got := filterInScope(candidates, nil)
	if len(got) != len(candidates) {
		t.Errorf("filterInScope(nil scope) dropped candidates, want passthrough")
	}
}

func TestScanner_ResolveRecordTypes(t *testing.T) {
	resolver := &mockResolver{records: map[string][]Record{
		"example.test|A":    {{Name: "example.test", Type: TypeA, Value: "192.0.2.10"}},
		"example.test|AAAA": {{Name: "example.test", Type: TypeAAAA, Value: "2001:db8::10"}},
	}}
	scanner := NewScanner(resolver, nil, testScannerConfig())

	results := scanner.resolveRecordTypes(context.Background(), uuid.New(), uuid.New(), "example.test", []RecordType{TypeA, TypeAAAA, TypeMX}, nil)

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	byType := map[RecordType]RecordResult{}
	for _, r := range results {
		byType[r.Type] = r
	}
	if byType[TypeA].State != StateResolved {
		t.Errorf("A state = %s, want RESOLVED", byType[TypeA].State)
	}
	if byType[TypeAAAA].State != StateResolved {
		t.Errorf("AAAA state = %s, want RESOLVED", byType[TypeAAAA].State)
	}
	if byType[TypeMX].State != StateNXDOMAIN {
		t.Errorf("MX state = %s, want NXDOMAIN (not present in mock)", byType[TypeMX].State)
	}
}

func TestScanner_ResolveSubdomain_WildcardAffectedExcludesFromSuccess(t *testing.T) {
	resolver := &mockResolver{
		records: map[string][]Record{
			"api.wildcard.example.test|A": {{Name: "api.wildcard.example.test", Type: TypeA, Value: "192.0.2.77"}},
		},
		wildcardDomain: "wildcard.example.test",
		wildcardValue:  "203.0.113.50",
	}
	scanner := NewScanner(resolver, nil, testScannerConfig())

	wildcard, err := DetectWildcard(context.Background(), resolver, "wildcard.example.test", []RecordType{TypeA})
	if err != nil || !wildcard.Detected {
		t.Fatalf("DetectWildcard: detected=%v err=%v", wildcard.Detected, err)
	}

	// A random, unconfigured name under the wildcard domain: resolves, but
	// must be flagged WildcardAffected and NOT counted as a genuine
	// discovery.
	noise := scanner.resolveSubdomain(context.Background(), uuid.New(), uuid.New(),
		SubdomainCandidate{Name: "random1.wildcard.example.test"}, []RecordType{TypeA}, wildcard)
	if !noise.WildcardAffected {
		t.Errorf("random subdomain under wildcard: WildcardAffected = false, want true")
	}
	if noise.Succeeded() {
		t.Errorf("random subdomain under wildcard: Succeeded() = true, want false")
	}

	// A distinct, explicitly-configured record under the same wildcard
	// domain must still be recognized as genuine (phase5.md §58).
	genuine := scanner.resolveSubdomain(context.Background(), uuid.New(), uuid.New(),
		SubdomainCandidate{Name: "api.wildcard.example.test"}, []RecordType{TypeA}, wildcard)
	if genuine.WildcardAffected {
		t.Errorf("distinct record under wildcard domain: WildcardAffected = true, want false")
	}
	if !genuine.Succeeded() {
		t.Errorf("distinct record under wildcard domain: Succeeded() = false, want true")
	}
}

func TestScanner_ResolveSubdomain_NXDOMAINShortCircuits(t *testing.T) {
	resolver := &mockResolver{records: map[string][]Record{}} // everything NXDOMAINs
	scanner := NewScanner(resolver, nil, testScannerConfig())

	result := scanner.resolveSubdomain(context.Background(), uuid.New(), uuid.New(),
		SubdomainCandidate{Name: "missing.example.test"}, []RecordType{TypeA, TypeAAAA, TypeMX}, WildcardDetection{})

	if result.State != StateNXDOMAIN {
		t.Errorf("State = %s, want NXDOMAIN", result.State)
	}
}

func TestDiscoveredIPs_DedupesAcrossRecordAndSubdomainResults(t *testing.T) {
	records := []RecordResult{
		{Records: []Record{{Type: TypeA, Value: "192.0.2.10"}}},
	}
	subdomains := []SubdomainResult{
		{Records: []Record{{Type: TypeA, Value: "192.0.2.10"}}}, // duplicate of above
		{Records: []Record{{Type: TypeAAAA, Value: "2001:db8::10"}}},
		{Records: []Record{{Type: TypeCNAME, Value: "other.example.test"}}}, // not an IP, must be excluded
	}

	ips := discoveredIPs(records, subdomains)

	if len(ips) != 2 {
		t.Fatalf("discoveredIPs() = %v, want 2 unique IPs", ips)
	}
}

func TestScanner_Scan_EndToEnd(t *testing.T) {
	resolver := &mockResolver{
		records: map[string][]Record{
			"example.test|A":     {{Name: "example.test", Type: TypeA, Value: "192.0.2.10"}},
			"api.example.test|A": {{Name: "api.example.test", Type: TypeA, Value: "192.0.2.20"}},
			"192.0.2.20|PTR":     {{Name: "192.0.2.20", Type: TypePTR, Value: "api.example.test"}},
		},
	}
	cfg := testScannerConfig()
	cfg.ReversePTR = true
	cfg.Subdomains.WildcardDetection = false // mockResolver has no wildcard configured; skip probing overhead
	scanner := NewScanner(resolver, nil, cfg)

	scope, err := discoveryhttp.NewScopeValidator("https://example.test")
	if err != nil {
		t.Fatalf("NewScopeValidator: %v", err)
	}

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetID:       uuid.New(),
		Domain:         "example.test",
		RecordTypes:    []RecordType{TypeA},
		SubdomainWords: []string{"api", "missing"},
	}, scope)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if summary.SubdomainsDiscovered != 1 {
		t.Errorf("SubdomainsDiscovered = %d, want 1 (api only; missing NXDOMAINs)", summary.SubdomainsDiscovered)
	}
	foundPTR := false
	for _, r := range summary.RecordResults {
		if r.Type == TypePTR && r.State == StateResolved {
			foundPTR = true
		}
	}
	if !foundPTR {
		t.Errorf("expected a resolved PTR record for the discovered A address, found none")
	}
}

func TestScanner_Scan_RespectsContextCancellation(t *testing.T) {
	resolver := &mockResolver{records: map[string][]Record{}}
	scanner := NewScanner(resolver, nil, testScannerConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Scan starts

	scope, err := discoveryhttp.NewScopeValidator("https://example.test")
	if err != nil {
		t.Fatalf("NewScopeValidator: %v", err)
	}

	summary, err := scanner.Scan(ctx, ScanRequest{Domain: "example.test", RecordTypes: []RecordType{TypeA}}, scope)
	if err != nil {
		t.Fatalf("Scan with cancelled context returned error (want a summary reflecting cancellation, not a hard failure): %v", err)
	}
	if summary.Resolved != 0 {
		t.Errorf("Resolved = %d, want 0 under an already-cancelled context", summary.Resolved)
	}
}

func TestRateLimiter_NilWhenDisabled(t *testing.T) {
	if newRateLimiter(0) != nil {
		t.Errorf("newRateLimiter(0) != nil, want nil (unlimited)")
	}
	if newRateLimiter(-1) != nil {
		t.Errorf("newRateLimiter(-1) != nil, want nil (unlimited)")
	}
}

func TestAwaitLimiter_NilAlwaysTrue(t *testing.T) {
	if !awaitLimiter(context.Background(), nil) {
		t.Errorf("awaitLimiter(nil limiter) = false, want true")
	}
}
