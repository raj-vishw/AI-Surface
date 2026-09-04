package endpoint

import "testing"

const testJS = `
async function loadUsers() {
  const res = await fetch("/api/users");
  return res.json();
}
axios.get("/api/v1/models").then(r => r.data);
const xhr = new XMLHttpRequest();
xhr.open("GET", "/auth/login");
const notAnEndpoint = "/not-an-endpoint";
// comment mentioning /some/path should still be caught as a weak string
const thirdParty = "https://cdn.example.net/lib.js";
`

func TestExtractJSRoutes_StrongSignals(t *testing.T) {
	results := ExtractJSRoutes(testJS)

	byPath := map[string]Candidate{}
	for _, r := range results {
		byPath[r.URL] = r
	}

	for _, path := range []string{"/api/users", "/api/v1/models", "/auth/login"} {
		c, ok := byPath[path]
		if !ok {
			t.Fatalf("expected a strong candidate for %q, got %v", path, results)
		}
		if c.Confidence != ConfidenceJSAPICall {
			t.Errorf("%s: Confidence = %v, want %v (strong call-site signal)", path, c.Confidence, ConfidenceJSAPICall)
		}
		if c.Inferred {
			t.Errorf("%s: Inferred = true, want false (a strong call-site match)", path)
		}
	}
}

func TestExtractJSRoutes_WeakStringGetsLowerConfidence(t *testing.T) {
	results := ExtractJSRoutes(testJS)
	var weak *Candidate
	for i, r := range results {
		if r.URL == "/not-an-endpoint" {
			weak = &results[i]
		}
	}
	if weak == nil {
		t.Fatalf("expected /not-an-endpoint as a weak candidate, got %v", results)
	}
	if weak.Confidence != ConfidenceJSStringLiteral {
		t.Errorf("Confidence = %v, want %v (weak string-literal signal)", weak.Confidence, ConfidenceJSStringLiteral)
	}
	if !weak.Inferred {
		t.Error("expected Inferred = true for a weak string-literal match")
	}
}

func TestExtractJSRoutes_ThirdPartyURLNotExtractedAsPath(t *testing.T) {
	results := ExtractJSRoutes(testJS)
	for _, r := range results {
		if r.URL == "https://cdn.example.net/lib.js" || r.URL == "//cdn.example.net/lib.js" {
			t.Errorf("a full external URL string should not be extracted as a bare path candidate: %+v", r)
		}
	}
}

func TestExtractJSRoutes_NoDoubleCounting(t *testing.T) {
	// /api/users appears only via fetch() in testJS — it must not also
	// appear as a separate weak-confidence duplicate.
	results := ExtractJSRoutes(testJS)
	count := 0
	for _, r := range results {
		if r.URL == "/api/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("/api/users appeared %d times, want exactly 1 (no double counting across tiers)", count)
	}
}

func TestExtractJSRoutes_NoEndpoints(t *testing.T) {
	results := ExtractJSRoutes(`console.log("hello world"); const x = 1 + 2;`)
	if len(results) != 0 {
		t.Errorf("expected no candidates from unrelated JS, got %v", results)
	}
}

func TestExtractJSRoutes_EmptySource(t *testing.T) {
	if results := ExtractJSRoutes(""); len(results) != 0 {
		t.Errorf("expected no candidates from empty source, got %v", results)
	}
}
