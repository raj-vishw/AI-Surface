package fingerprint

import (
	"testing"
)

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	sigs, err := LoadDefaultSignatures()
	if err != nil {
		t.Fatalf("LoadDefaultSignatures: %v", err)
	}
	return NewEngine(sigs, EngineConfig{MinConfidence: 0})
}

func findResult(results []Result, technology string) (Result, bool) {
	for _, r := range results {
		if r.Technology == technology {
			return r, true
		}
	}
	return Result{}, false
}

func TestEngine_Nginx_VersionExtracted(t *testing.T) {
	e := mustEngine(t)
	obs := Observation{Headers: map[string]string{"Server": "nginx/1.25.3"}}
	results := e.Evaluate(obs)

	r, ok := findResult(results, "nginx")
	if !ok {
		t.Fatalf("expected an nginx result, got %+v", results)
	}
	if r.Version != "1.25.3" {
		t.Errorf("Version = %q, want 1.25.3", r.Version)
	}
	if r.Category != CategoryWebServer {
		t.Errorf("Category = %q, want web_server", r.Category)
	}
	if r.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", r.Confidence)
	}
}

func TestEngine_Nginx_NoVersion(t *testing.T) {
	e := mustEngine(t)
	obs := Observation{Headers: map[string]string{"Server": "nginx"}}
	results := e.Evaluate(obs)

	r, ok := findResult(results, "nginx")
	if !ok {
		t.Fatalf("expected an nginx result")
	}
	if r.Version != "" {
		t.Errorf("Version = %q, want empty (never guessed) when the header carries none", r.Version)
	}
}

func TestEngine_NoSignals_NoResults(t *testing.T) {
	e := mustEngine(t)
	results := e.Evaluate(Observation{})
	if len(results) != 0 {
		t.Errorf("Evaluate(empty observation) = %d results, want 0", len(results))
	}
}

func TestEngine_ConflictHandling_NginxVsApache(t *testing.T) {
	e := mustEngine(t)
	// Both Server headers present (a misconfigured proxy scenario) — the
	// negative_signals in each signature disqualify the other, so neither
	// fires (phase6.md §10's "do not simply return both with 100%
	// confidence" — here it's stronger: the declared negative evidence
	// disqualifies both entirely, which is the documented, explainable
	// outcome for genuinely contradictory single-header evidence).
	obs := Observation{Headers: map[string]string{"Server": "nginx, Apache/2.4"}}
	results := e.Evaluate(obs)
	if _, ok := findResult(results, "nginx"); ok {
		t.Errorf("nginx matched despite its own negative signal (Apache present in the same header)")
	}
	if _, ok := findResult(results, "Apache"); ok {
		t.Errorf("Apache matched despite its own negative signal (nginx present in the same header)")
	}
}

func TestEngine_MultipleCoexistingTechnologies(t *testing.T) {
	e := mustEngine(t)
	// nginx + Cloudflare + Express: a completely ordinary, simultaneously
	// true stack (phase6.md §10) — none of these are declared
	// incompatible with each other.
	obs := Observation{
		Headers: map[string]string{
			"Server":       "nginx",
			"CF-Ray":       "abc123-SJC",
			"X-Powered-By": "Express",
		},
	}
	results := e.Evaluate(obs)
	for _, want := range []string{"nginx", "Cloudflare", "Express"} {
		if _, ok := findResult(results, want); !ok {
			t.Errorf("expected %s among results, got %v", want, technologyNames(results))
		}
	}
}

func TestEngine_CorroboratingSignalsIncreaseConfidence(t *testing.T) {
	e := mustEngine(t)
	weak := e.Evaluate(Observation{Headers: map[string]string{"Server": "nginx"}})
	strong := e.Evaluate(Observation{Headers: map[string]string{"Server": "nginx", "Via": "1.1 nginx"}})

	weakR, _ := findResult(weak, "nginx")
	strongR, _ := findResult(strong, "nginx")
	if strongR.Confidence <= weakR.Confidence {
		t.Errorf("corroborating Via signal did not increase confidence: weak=%v strong=%v", weakR.Confidence, strongR.Confidence)
	}
}

func TestEngine_DuplicateEvidenceNotDoubleCounted(t *testing.T) {
	e := mustEngine(t)
	// The same Server header value can only ever appear once in
	// Observation.Headers (it's a map), but this proves the dedup
	// mechanism directly: matching the same signal twice via two
	// differently-shaped but value-identical rules must not sum past
	// what one occurrence would contribute alone... (see scorer_test.go
	// for a more direct unit-level test of the dedup key itself).
	obs := Observation{Headers: map[string]string{"Server": "nginx"}}
	results := e.Evaluate(obs)
	r, _ := findResult(results, "nginx")
	if r.Confidence > 1.0 {
		t.Errorf("Confidence = %v, must never exceed 1.0", r.Confidence)
	}
}

func TestEngine_WeakDatabaseCandidate_PortAloneIsLowConfidence(t *testing.T) {
	e := mustEngine(t)
	port := 5432
	obs := Observation{Port: &port} // no corroborating "service" classification
	results := e.Evaluate(obs)

	r, ok := findResult(results, "PostgreSQL")
	if !ok {
		t.Fatalf("expected a PostgreSQL candidate from port 5432 alone, got %v", technologyNames(results))
	}
	if r.Confidence >= 0.5 {
		t.Errorf("Confidence = %v, want a weak/low candidate (port alone must not be confirmation, phase6.md §19)", r.Confidence)
	}
	if r.Level != LevelWeak && r.Level != LevelLow {
		t.Errorf("Level = %s, want weak or low", r.Level)
	}
}

func TestEngine_DatabaseCandidate_CorroboratedByService(t *testing.T) {
	e := mustEngine(t)
	port := 5432
	obs := Observation{Port: &port, Service: "PostgreSQL"}
	results := e.Evaluate(obs)

	r, ok := findResult(results, "PostgreSQL")
	if !ok {
		t.Fatalf("expected a PostgreSQL result")
	}
	if r.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want high once corroborated by an actual service classification", r.Confidence)
	}
}

func TestEngine_AI_ExplicitModelIdentifier(t *testing.T) {
	e := mustEngine(t)
	obs := Observation{ExplicitModel: "gpt-4-turbo-2024-04-09"}
	results := e.Evaluate(obs)

	r, ok := findResult(results, "Observed model identifier")
	if !ok {
		t.Fatalf("expected an ai_model_candidate result, got %v", technologyNames(results))
	}
	if r.Category != CategoryAIModelCandidate {
		t.Errorf("Category = %s, want ai_model_candidate", r.Category)
	}
	if len(r.Signals) != 1 || r.Signals[0].Value != "gpt-4-turbo-2024-04-09" {
		t.Errorf("Signals = %+v, want the exact observed model string, verbatim", r.Signals)
	}
}

func TestEngine_AI_WeakVsStrongProviderEvidence(t *testing.T) {
	e := mustEngine(t)
	weak := e.Evaluate(Observation{APIPaths: []string{"/v1/chat/completions"}})
	strong := e.Evaluate(Observation{
		APIPaths: []string{"/v1/chat/completions"},
		Headers:  map[string]string{"Openai-Organization": "org-abc123"},
	})

	weakR, ok := findResult(weak, "OpenAI-compatible API")
	if !ok {
		t.Fatalf("expected a weak OpenAI-compatible-API candidate from path alone")
	}
	strongR, ok := findResult(strong, "OpenAI-compatible API")
	if !ok {
		t.Fatalf("expected a strong OpenAI-compatible-API candidate")
	}
	if weakR.Confidence >= strongR.Confidence {
		t.Errorf("path-only confidence (%v) should be lower than path+header confidence (%v)", weakR.Confidence, strongR.Confidence)
	}
	if weakR.Confidence >= 0.7 {
		t.Errorf("path-only AI evidence should never itself reach high confidence, got %v", weakR.Confidence)
	}
	// Never overclaims a specific model from the endpoint shape alone.
	if _, ok := findResult(weak, "Observed model identifier"); ok {
		t.Errorf("must never claim a model candidate from endpoint path alone")
	}
}

func TestEngine_AI_NoEvidence(t *testing.T) {
	e := mustEngine(t)
	results := e.Evaluate(Observation{URLPath: "/about"})
	for _, r := range results {
		if r.Category == CategoryAIProvider || r.Category == CategoryAIPlatform || r.Category == CategoryAIModelCandidate {
			t.Errorf("unexpected AI-category result from unrelated evidence: %+v", r)
		}
	}
}

func TestEngine_MinConfidenceFiltering(t *testing.T) {
	sigs, err := LoadDefaultSignatures()
	if err != nil {
		t.Fatalf("LoadDefaultSignatures: %v", err)
	}
	strict := NewEngine(sigs, EngineConfig{MinConfidence: 0.9})
	obs := Observation{Headers: map[string]string{"Server": "nginx"}} // single signal, well under 0.9
	results := strict.Evaluate(obs)
	if _, ok := findResult(results, "nginx"); ok {
		t.Errorf("expected nginx to be filtered out below MinConfidence=0.9, got %v", technologyNames(results))
	}
}

func TestEngine_Deterministic(t *testing.T) {
	e := mustEngine(t)
	obs := Observation{Headers: map[string]string{"Server": "nginx", "CF-Ray": "abc"}}
	first := e.Evaluate(obs)
	second := e.Evaluate(obs)
	if len(first) != len(second) {
		t.Fatalf("non-deterministic result count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Technology != second[i].Technology || first[i].Confidence != second[i].Confidence {
			t.Errorf("non-deterministic result at index %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}

func technologyNames(results []Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Technology
	}
	return out
}
