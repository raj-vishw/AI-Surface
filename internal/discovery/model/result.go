// Package model defines the HTTP discovery engine's result types — the
// data that flows from internal/discovery/http out to the CLI (table/JSON
// output) and to internal/discovery/service (persistence through Phase 2).
package model

import (
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/httpclient"
)

// ServiceType classifies what an HTTP response looks like, based only on
// observable evidence (path, headers, content type, response shape) —
// never a specific product/vendor/model claim. See
// internal/discovery/http/analyzer.go.
type ServiceType string

// Recognized service classifications.
const (
	ServiceUnknown        ServiceType = "UNKNOWN"
	ServiceWebApplication ServiceType = "WEB_APPLICATION"
	ServiceAPI            ServiceType = "API"
	ServiceJSONAPI        ServiceType = "JSON_API"
	ServiceDocumentation  ServiceType = "DOCUMENTATION"
	ServiceHealthEndpoint ServiceType = "HEALTH_ENDPOINT"
	ServiceAICandidate    ServiceType = "AI_CANDIDATE"
)

// Result is one candidate URL's discovery outcome — either a completed
// HTTP observation or a structured failure. Exactly one of the "success"
// fields (StatusCode, ContentType, ...) or Error is meaningful at a time;
// Error is non-empty if and only if the request did not complete.
//
// The full response body is never retained here by design (phase3.md
// §14/§23) — only metadata, a hash, and the specific structured indicators
// the classifier extracted.
type Result struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID

	Method string
	URL    string // the exact candidate URL requested

	FinalURL      string // URL after any followed redirects
	StatusCode    int
	Headers       map[string][]string // sanitized — see internal/domain/asset.SanitizeMetadata
	ContentType   string
	ContentLength int64
	ResponseHash  string // sha256 hex, empty if the request failed
	Duration      time.Duration

	TLSMetadata     *httpclient.TLSMetadata
	RedirectChain   []string
	RedirectBlocked bool // a hop was refused by scope validation — see ScopeValidator

	// CookieNames holds every distinct cookie *name* set via Set-Cookie —
	// never a value (phase6.md §13/§31: cookie fingerprinting must never
	// persist a cookie's value). Extracted from the raw, pre-redaction
	// response headers, since Headers itself replaces Set-Cookie's entire
	// value with "[REDACTED]" (see sanitizeHeaders) — by the time Headers
	// is populated, the name is no longer recoverable from it.
	CookieNames []string

	// Cookies holds each Set-Cookie's *attributes* only (Secure/HttpOnly/
	// SameSite) — never a value, for the identical reason CookieNames
	// never carries one (phase8.md §22/§23: Phase 8's cookie-security
	// detector needs these to evaluate configuration without ever storing
	// what a cookie actually contains).
	Cookies []CookieAttribute

	ServiceType         ServiceType
	Indicators          []string // human-readable evidence for ServiceType/AIEndpointCandidate
	AIEndpointCandidate bool
	Confidence          float64

	ObservedAt time.Time

	// Error is set when the request failed outright (connection refused,
	// DNS failure, TLS failure, timeout, response too large, context
	// cancellation, scope violation, ...). A non-2xx/3xx/4xx/5xx HTTP
	// response is NOT an error — it's a normal Result with StatusCode set.
	Error string

	// Skipped is set when a candidate was intentionally never requested
	// (e.g. it failed scope validation before any connection was made).
	// SkippedReason explains why.
	Skipped       bool
	SkippedReason string
}

// Succeeded reports whether r represents a completed HTTP request (as
// opposed to a transport failure or a skipped candidate).
func (r Result) Succeeded() bool {
	return r.Error == "" && !r.Skipped
}

// CookieAttribute is one Set-Cookie's name and security-relevant
// attributes — deliberately never its value (phase6.md §13/§31,
// phase8.md §23).
type CookieAttribute struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string // "Strict", "Lax", "None", or "" if unset
}

// Summary aggregates every Result from one discovery run.
type Summary struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID
	Target   string

	URLsAttempted int
	Successful    int
	Failed        int

	HTTPEndpoints int
	APICandidates int
	AICandidates  int
	Redirects     int
	Errors        int

	Duration time.Duration

	Results []Result
}
