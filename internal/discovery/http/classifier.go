package http

import (
	"fmt"
	"strings"
)

// aiCandidatePaths are normalized path patterns whose presence alone is
// meaningful evidence of an AI-related endpoint. This is pattern matching
// only — it never identifies a specific provider or model (phase3.md
// §17/§51).
var aiCandidatePaths = map[string]bool{
	"/v1/models": true, "/v1/chat/completions": true, "/v1/completions": true,
	"/v1/embeddings": true, "/chat/completions": true, "/api/chat": true,
	"/api/generate": true, "/models": true,
}

// aiResponseFields are JSON field names commonly present in AI/LLM API
// responses (OpenAI-compatible and similar schemas). Presence is an
// indicator, never proof of a specific provider or model.
var aiResponseFields = []string{
	"choices", "messages", "model", "usage", "prompt_tokens",
	"completion_tokens", "embedding", "object", "created",
}

// Indicator weights for AI candidate confidence scoring — deterministic
// and documented (see docs/architecture/http-discovery.md "AI Candidate
// Detection"). No LLM or machine learning is involved (phase3.md §18).
// Weights sum to 1.0 exactly so a fully-corroborated response always
// scores exactly 1.0 without needing to clamp; ClassifyAICandidate clamps
// defensively regardless.
const (
	weightPathIndicator        = 0.35 // path matches a known AI/LLM API pattern
	weightContentTypeIndicator = 0.15 // response content-type is JSON
	weightSchemaIndicator      = 0.30 // at least one known AI-response field present
	weightSchemaBonusIndicator = 0.20 // at least three known AI-response fields present
)

// aiCandidateThreshold is the minimum confidence for AIEndpointCandidate
// to be true. It is set so the path indicator alone (0.35), or the schema
// indicator alone (0.30), is independently sufficient evidence — but the
// content-type indicator alone (0.15, very weak: an enormous number of
// ordinary, non-AI APIs also return application/json) is not.
const aiCandidateThreshold = 0.30

// AIAnalysis is the result of AI endpoint candidate detection.
type AIAnalysis struct {
	Candidate     bool
	Confidence    float64
	Evidence      []string
	MatchedFields []string
}

// ClassifyAICandidate deterministically scores path and response-shape
// evidence for how strongly a candidate resembles an AI/LLM API endpoint.
// It never identifies a provider or model — that is fingerprinting and
// belongs to a later phase (phase3.md §51).
func ClassifyAICandidate(path string, isJSON bool, jsonBody map[string]any) AIAnalysis {
	var (
		score    float64
		evidence []string
		matched  []string
	)

	if aiCandidatePaths[path] {
		score += weightPathIndicator
		evidence = append(evidence, "path resembles a known AI/LLM API pattern ("+path+")")
	}

	if isJSON {
		score += weightContentTypeIndicator
		evidence = append(evidence, "response content-type is JSON")
	}

	for _, field := range aiResponseFields {
		if _, ok := jsonBody[field]; ok {
			matched = append(matched, field)
		}
	}
	if len(matched) >= 1 {
		score += weightSchemaIndicator
		evidence = append(evidence, fmt.Sprintf("response body contains %d known AI-response field(s): %s", len(matched), strings.Join(matched, ", ")))
	}
	if len(matched) >= 3 {
		score += weightSchemaBonusIndicator
		evidence = append(evidence, "response body schema resembles a chat/completion API (3+ matching fields)")
	}

	if score > 1.0 {
		score = 1.0
	}

	return AIAnalysis{
		Candidate:     score >= aiCandidateThreshold,
		Confidence:    score,
		Evidence:      evidence,
		MatchedFields: matched,
	}
}
