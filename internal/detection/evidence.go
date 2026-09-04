package detection

// EvidenceType classifies what kind of observation an Evidence value
// captures (phase8.md §9) — the same closed vocabulary
// internal/domain/finding.EvidenceType uses, kept as an independent copy
// for this package's self-contained-engine discipline.
type EvidenceType string

// Recognized evidence types.
const (
	EvidenceHTTPHeader      EvidenceType = "http_header"
	EvidenceHTTPStatus      EvidenceType = "http_status"
	EvidenceResponseMeta    EvidenceType = "response_metadata"
	EvidenceTLSMetadata     EvidenceType = "tls_metadata"
	EvidenceCookieMetadata  EvidenceType = "cookie_metadata"
	EvidenceEndpointMeta    EvidenceType = "endpoint_metadata"
	EvidenceTechnology      EvidenceType = "technology_fingerprint"
	EvidenceServiceMeta     EvidenceType = "service_observation"
	EvidenceOpenAPIMeta     EvidenceType = "openapi_metadata"
	EvidenceClassification  EvidenceType = "endpoint_classification"
	EvidenceConfiguration   EvidenceType = "configuration_observation"
	EvidenceResponseExcerpt EvidenceType = "response_excerpt"
)

// Evidence is one piece of support for a Finding (phase8.md §8: "Evidence
// must explain why the finding exists"). Data must never carry a full
// response body, a credential, or a cookie/header value already redacted
// upstream by Phase 2's SanitizeMetadata boundary — see cookies.go and
// exposed_files.go/error_disclosure.go for how safe-active detectors keep
// excerpts short and sanitized before they ever become Evidence.
type Evidence struct {
	Type       EvidenceType
	Data       map[string]any
	Confidence Confidence
}

// NewEvidence builds an Evidence value.
func NewEvidence(t EvidenceType, data map[string]any, confidence Confidence) Evidence {
	return Evidence{Type: t, Data: data, Confidence: confidence}
}

// TruncateExcerpt bounds s to maxLen runes, appending a truncation marker
// when it cuts s short. Every safe-active detector must run any body
// content through this (or an equivalent bound) before attaching it as
// Evidence — the full response is never retained (phase8.md §9/§27).
func TruncateExcerpt(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = DefaultMaxExcerptLength
	}
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return string(r[:maxLen]) + "...[truncated]"
}
