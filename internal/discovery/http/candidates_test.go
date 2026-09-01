package http

import (
	"net/url"
	"testing"
	"time"

	domaintarget "ai-recon-platform/internal/domain/target"
)

func testConfig() Config {
	return Config{
		Timeout: time.Second, MaxConcurrency: 5, MaxResponseSize: 1024,
		FollowRedirects: true, MaxRedirects: 5,
		Methods: []string{"GET"}, Schemes: []string{"https", "http"},
	}
}

func mustScope(t *testing.T, target string) *ScopeValidator {
	t.Helper()
	v, err := NewScopeValidator(target)
	if err != nil {
		t.Fatalf("NewScopeValidator(%q): %v", target, err)
	}
	return v
}

func TestGenerateCandidates_URLTargetRootAndPaths(t *testing.T) {
	scope := mustScope(t, "http://example.test")
	candidates, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), []string{"/", "/health"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]bool{"http://example.test/": false, "http://example.test/health": false}
	if len(candidates) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(candidates), len(want), candidates)
	}
	for _, c := range candidates {
		if _, ok := want[c.URL]; !ok {
			t.Errorf("unexpected candidate %s", c.URL)
		}
		want[c.URL] = true
	}
	for u, seen := range want {
		if !seen {
			t.Errorf("missing candidate %s", u)
		}
	}
}

func TestGenerateCandidates_DuplicatePathsCollapse(t *testing.T) {
	scope := mustScope(t, "http://example.test")
	// "/api" and "/api/" normalize to the same canonical URL (see
	// endpoint.Normalize's trailing-slash policy), so they must collapse
	// to a single candidate.
	candidates, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), []string{"/api", "/api/"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected duplicate paths to collapse to 1 candidate, got %d: %+v", len(candidates), candidates)
	}
}

func TestGenerateCandidates_HostTargetUsesEveryConfiguredScheme(t *testing.T) {
	scope := mustScope(t, "https://example.test")
	candidates, err := GenerateCandidates(domaintarget.TypeDomain, "example.test", testConfig(), []string{"/"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected one candidate per configured scheme (https, http), got %d: %+v", len(candidates), candidates)
	}
	schemes := map[string]bool{}
	for _, c := range candidates {
		u, err := url.Parse(c.URL)
		if err != nil {
			t.Fatalf("candidate URL %q did not parse: %v", c.URL, err)
		}
		schemes[u.Scheme] = true
	}
	if !schemes["https"] || !schemes["http"] {
		t.Errorf("expected both configured schemes to be tried, got %+v", candidates)
	}
}

func TestGenerateCandidates_URLTargetIgnoresConfiguredSchemes(t *testing.T) {
	scope := mustScope(t, "http://example.test")
	// cfg.Schemes lists both https and http, but an explicit URL target
	// must use exactly its own scheme (phase3.md §8) — not silently probe
	// the other one too.
	candidates, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), []string{"/"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("URL target should produce exactly 1 candidate for 1 path, got %d: %+v", len(candidates), candidates)
	}
	if candidates[0].URL != "http://example.test/" {
		t.Errorf("candidate URL = %q, want the target's own scheme preserved", candidates[0].URL)
	}
}

func TestGenerateCandidates_UnsupportedTargetType(t *testing.T) {
	if _, err := GenerateCandidates(domaintarget.TypeIP, "10.0.0.1", testConfig(), []string{"/"}, nil); err == nil {
		t.Fatal("expected an error for an unsupported target type (only URL/HOST/DOMAIN are supported)")
	}
}

func TestGenerateCandidates_ScopeFiltersOutOfScopeBase(t *testing.T) {
	// A scope validator built against a different host than the target
	// must result in zero candidates — every generated candidate is
	// checked before being included (phase3.md §11).
	scope := mustScope(t, "http://other.test")
	candidates, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), []string{"/"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected scope to filter out every candidate, got %+v", candidates)
	}
}

func TestGenerateCandidates_Deterministic(t *testing.T) {
	scope := mustScope(t, "http://example.test")
	paths := []string{"/z", "/a", "/m"}
	first, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), paths, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), paths, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic length: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic order at index %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}

func TestGenerateCandidates_FragmentsRemoved(t *testing.T) {
	scope := mustScope(t, "http://example.test")
	candidates, err := GenerateCandidates(domaintarget.TypeURL, "http://example.test", testConfig(), []string{"/page"}, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range candidates {
		if u, _ := url.Parse(c.URL); u.Fragment != "" {
			t.Errorf("candidate %q retained a fragment", c.URL)
		}
	}
}
