package endpoint

// AIAPIBaseConfidence is the confidence assigned when a candidate's path
// alone matches a known AI-oriented API shape (phase7.md §50's own worked
// example: "classification: ai_api_candidate, confidence: 0.45") — never
// higher from path shape alone, and never a claim that a specific
// provider or model is present. internal/discovery/service/endpoint.go
// independently raises this when Phase 6 fingerprint evidence
// corroborates an AI provider on the same asset (phase7.md §50: "if
// existing HTTP evidence independently supports an AI provider,
// confidence may increase") — this package has no dependency on
// internal/fingerprint (the same "engine stays self-contained" rule
// every discovery engine in this project follows), so that corroboration
// step lives one layer up, not here.
const AIAPIBaseConfidence = 0.45

// AIAPIType is the APIType value recorded for an AI-candidate endpoint —
// distinct from "rest"/"graphql"/"openapi"/"swagger", so a caller can
// always tell an AI-shaped candidate apart from an ordinary REST
// endpoint that merely happens to also match /api/ (phase7.md §50).
const AIAPIType = "ai_api_candidate"
