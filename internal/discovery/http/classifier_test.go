package http

import (
	"strings"
	"testing"
)

func TestClassifyAICandidate_PositiveFullResponse(t *testing.T) {
	body := map[string]any{
		"id": "x", "object": "chat.completion", "model": "test",
		"choices": []any{}, "usage": map[string]any{},
	}
	result := ClassifyAICandidate("/v1/chat/completions", true, body)
	if !result.Candidate {
		t.Error("expected candidate=true for a full AI-shaped response")
	}
	if result.Confidence < aiCandidateThreshold {
		t.Errorf("confidence %v below threshold %v", result.Confidence, aiCandidateThreshold)
	}
}

func TestClassifyAICandidate_NegativeResponse(t *testing.T) {
	body := map[string]any{"name": "widget", "price": 9.99}
	result := ClassifyAICandidate("/api/products", true, body)
	if result.Candidate {
		t.Error("expected candidate=false for an ordinary, non-AI-shaped API response")
	}
}

func TestClassifyAICandidate_PathOnlyIndicator(t *testing.T) {
	result := ClassifyAICandidate("/v1/models", false, nil)
	if !result.Candidate {
		t.Error("path indicator alone should be sufficient evidence")
	}
}

func TestClassifyAICandidate_SchemaOnlyIndicator(t *testing.T) {
	body := map[string]any{"choices": []any{}, "usage": map[string]any{}, "model": "x"}
	result := ClassifyAICandidate("/some/unrelated/path", false, body)
	if !result.Candidate {
		t.Error("3+ matching schema fields alone should be sufficient evidence")
	}
}

func TestClassifyAICandidate_ContentTypeAloneInsufficient(t *testing.T) {
	result := ClassifyAICandidate("/some/path", true, nil)
	if result.Candidate {
		t.Error("content-type alone must not be sufficient evidence (too weak on its own)")
	}
}

func TestClassifyAICandidate_MultipleIndicatorsIncreaseConfidence(t *testing.T) {
	pathOnly := ClassifyAICandidate("/v1/models", false, nil)
	pathAndSchema := ClassifyAICandidate("/v1/models", true, map[string]any{"model": "x", "object": "list"})
	if pathAndSchema.Confidence <= pathOnly.Confidence {
		t.Errorf("multiple indicators should increase confidence: %v (multi) vs %v (path only)", pathAndSchema.Confidence, pathOnly.Confidence)
	}
}

func TestClassifyAICandidate_ConfidenceNeverExceedsOne(t *testing.T) {
	body := map[string]any{}
	for _, f := range aiResponseFields {
		body[f] = "x"
	}
	result := ClassifyAICandidate("/v1/chat/completions", true, body)
	if result.Confidence > 1.0 {
		t.Errorf("confidence must be clamped to 1.0, got %v", result.Confidence)
	}
}

func TestClassifyAICandidate_NoIndicators(t *testing.T) {
	result := ClassifyAICandidate("/", false, nil)
	if result.Candidate {
		t.Error("no indicators present should never be a candidate")
	}
	if result.Confidence != 0 {
		t.Errorf("expected 0 confidence with no indicators, got %v", result.Confidence)
	}
	if len(result.Evidence) != 0 {
		t.Errorf("expected no evidence with no indicators, got %+v", result.Evidence)
	}
}

func TestClassifyAICandidate_NeverIdentifiesProvider(t *testing.T) {
	// phase3.md §17/§51: candidate detection must never claim a specific
	// provider or model, even when the response itself names one.
	body := map[string]any{"choices": []any{}, "model": "gpt-4", "object": "chat.completion"}
	result := ClassifyAICandidate("/v1/chat/completions", true, body)
	for _, e := range result.Evidence {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "openai") || strings.Contains(lower, "gpt") || strings.Contains(lower, "anthropic") {
			t.Errorf("evidence must never name a specific provider/model, got: %q", e)
		}
	}
}
