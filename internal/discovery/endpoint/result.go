package endpoint

import (
	"time"

	"github.com/google/uuid"
)

// Classification mirrors internal/domain/endpoint.Classification's string
// vocabulary exactly, kept as an independent type per this package's
// no-domain-dependency rule (the same split every discovery engine in
// this project follows relative to internal/domain — phase7.md §4/§32).
type Classification string

// Recognized classifications.
const (
	ClassPage               Classification = "page"
	ClassAPI                Classification = "api"
	ClassGraphQL            Classification = "graphql"
	ClassOpenAPI            Classification = "openapi"
	ClassSwagger            Classification = "swagger"
	ClassAuth               Classification = "auth"
	ClassStatic             Classification = "static"
	ClassAsset              Classification = "asset"
	ClassDocumentation      Classification = "documentation"
	ClassSitemap            Classification = "sitemap"
	ClassRobots             Classification = "robots"
	ClassWebSocketCandidate Classification = "websocket_candidate"
	ClassUnknown            Classification = "unknown"
)

// Parameter is one observed parameter name — never a value (phase7.md
// §9/§37).
type Parameter struct {
	Name     string
	Location string // "query", "path", "form"
}

// Candidate is one URL+method the crawler will (or already did) fetch or
// record — the engine's unit of work before scope validation/
// normalization/deduplication collapse it into a Result.
type Candidate struct {
	URL string // raw, as found — relative or absolute, not yet resolved/normalized
	// Base is the absolute URL of the page/document this candidate was
	// discovered on — required to resolve a relative URL (an <a
	// href="/about">, an OpenAPI path) into an absolute one before
	// normalization/scope-checking. Empty for candidates that are
	// already absolute (seed URLs).
	Base       string
	Method     string
	Source     string // "seed", "html_link", "html_form", "javascript", "sitemap", "robots", "openapi", "swagger", "redirect"
	Confidence float64
	Depth      int
	// Documented/Inferred carry forward from the source that produced
	// this candidate (phase7.md §46/§47) — e.g. an OpenAPI-sourced
	// candidate is Documented; a weak JavaScript string match is
	// Inferred. Observed is never true here — it only becomes true once
	// (if) the candidate is actually fetched successfully.
	Documented bool
	Inferred   bool
	// Evidence is a short, human-readable, already-sanitized snippet
	// explaining why this candidate was generated (phase7.md §42) — e.g.
	// `<a href="/users">` or `fetch("/api/users")`.
	Evidence string
	// Parameters observed on this specific candidate (query string names,
	// or form field names when Source == "html_form").
	Parameters []Parameter
}

// Result is one logical endpoint's final, merged outcome — the engine's
// output unit, before internal/service/asset translates it into a
// persisted internal/domain/endpoint.Endpoint (+ Evidence + Parameters).
type Result struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID

	URL          string // normalized (internal/domain/endpoint.Normalize's canonical form)
	Scheme       string
	Host         string
	Port         int
	Path         string
	QueryPattern string
	Method       string

	StatusCode    *int // nil if never actually requested (documented/inferred only)
	ContentType   string
	ContentLength *int64
	ResponseHash  string

	Classification Classification
	APIType        string
	APIVersion     string

	Sources    []string
	Confidence float64
	Documented bool
	Observed   bool
	Inferred   bool
	Truncated  bool // the response was cut off at MaxResponseSize

	Parameters []Parameter
	// Evidence holds one sanitized snippet per contributing source (the
	// same key used in Sources), for --explain-style output and
	// evidence-row persistence.
	Evidence map[string]string

	// Error carries a transport-level failure description when Observed
	// is false because a fetch was attempted but failed (phase7.md §82) —
	// distinct from a candidate that was never fetched at all
	// (StatusCode nil, Error empty, Documented/Inferred true).
	Error string

	ObservedAt time.Time
}

// Succeeded reports whether r represents a completed HTTP request.
func (r Result) Succeeded() bool {
	return r.Observed && r.Error == ""
}

// Summary aggregates one endpoint discovery run.
type Summary struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID
	Target   string

	PagesFetched        int
	EndpointsDiscovered int
	Errors              int
	ScopeRejections     int
	Redirects           int
	Duplicates          int
	Truncated           int

	Duration time.Duration
	Results  []Result
}
