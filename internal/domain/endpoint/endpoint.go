// Package endpoint defines the Endpoint domain model: a specific
// network/application endpoint (method + URL) observed on an Asset, along
// with deterministic URL normalization used both for identity/deduplication
// and for storage.
package endpoint

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Method is an HTTP method.
type Method string

// Recognized HTTP methods.
const (
	MethodGet     Method = "GET"
	MethodPost    Method = "POST"
	MethodPut     Method = "PUT"
	MethodPatch   Method = "PATCH"
	MethodDelete  Method = "DELETE"
	MethodHead    Method = "HEAD"
	MethodOptions Method = "OPTIONS"
)

var validMethods = map[Method]bool{
	MethodGet: true, MethodPost: true, MethodPut: true, MethodPatch: true,
	MethodDelete: true, MethodHead: true, MethodOptions: true,
}

// Valid reports whether m is a recognized HTTP method.
func (m Method) Valid() bool { return validMethods[m] }

// Status mirrors asset.Status's lifecycle vocabulary. It is a distinct type
// (rather than an import of the asset package) so the endpoint domain has
// no dependency on the asset domain — only asset depends on endpoint, for
// URL identity — keeping the dependency graph one-directional.
type Status string

// Recognized endpoint statuses.
const (
	StatusDiscovered Status = "DISCOVERED"
	StatusActive     Status = "ACTIVE"
	StatusInactive   Status = "INACTIVE"
	StatusUnknown    Status = "UNKNOWN"
	StatusRetired    Status = "RETIRED"
)

var validStatuses = map[Status]bool{
	StatusDiscovered: true, StatusActive: true, StatusInactive: true,
	StatusUnknown: true, StatusRetired: true,
}

// Valid reports whether s is a recognized endpoint status.
func (s Status) Valid() bool { return validStatuses[s] }

// Classification names what kind of thing an endpoint appears to be
// (phase7.md §32) — deliberately coarse; "unknown" is an acceptable,
// honest answer, never forced into a more specific bucket without
// evidence.
type Classification string

// Recognized endpoint classifications.
const (
	ClassificationPage               Classification = "page"
	ClassificationAPI                Classification = "api"
	ClassificationGraphQL            Classification = "graphql"
	ClassificationOpenAPI            Classification = "openapi"
	ClassificationSwagger            Classification = "swagger"
	ClassificationAuth               Classification = "auth"
	ClassificationStatic             Classification = "static"
	ClassificationAsset              Classification = "asset"
	ClassificationDocumentation      Classification = "documentation"
	ClassificationSitemap            Classification = "sitemap"
	ClassificationRobots             Classification = "robots"
	ClassificationWebSocketCandidate Classification = "websocket_candidate"
	ClassificationUnknown            Classification = "unknown"
)

var validClassifications = map[Classification]bool{
	ClassificationPage: true, ClassificationAPI: true, ClassificationGraphQL: true,
	ClassificationOpenAPI: true, ClassificationSwagger: true, ClassificationAuth: true,
	ClassificationStatic: true, ClassificationAsset: true, ClassificationDocumentation: true,
	ClassificationSitemap: true, ClassificationRobots: true, ClassificationWebSocketCandidate: true,
	ClassificationUnknown: true,
}

// Valid reports whether c is a recognized classification.
func (c Classification) Valid() bool { return c == "" || validClassifications[c] }

// Endpoint represents a network/application endpoint associated with an
// Asset. URL, Scheme, Host, Port, Path, and QueryPattern are always the
// normalized form (see Normalize) — never the raw, as-observed URL; Path
// IS the normalized path already (phase7.md's "NormalizedPath" concept —
// this package deliberately does not carry a second, redundant column for
// it).
//
// Documented/Observed/Inferred (phase7.md §46/§47) are independent,
// non-exclusive facts about how this endpoint came to be known: an
// endpoint can be both Documented (named in an OpenAPI spec) and Observed
// (an actual HTTP response was received for it), or Documented alone (the
// spec names it but crawling never reached it), or Inferred alone (a weak
// JavaScript string match, nothing else corroborates it yet). Sources
// lists every discovery source that has ever contributed to this
// endpoint (phase7.md §40 — one logical endpoint, not one row per
// source).
type Endpoint struct {
	ID            uuid.UUID
	AssetID       uuid.UUID
	ScanID        *uuid.UUID
	URL           string
	Method        Method
	Scheme        string
	Host          string
	Port          int
	Path          string
	QueryPattern  string
	ContentType   string
	ContentLength *int64
	StatusCode    *int
	ResponseHash  string

	Classification Classification
	APIType        string // "rest", "graphql", "openapi", "swagger", "" (unknown)
	APIVersion     string // "" (never guessed — see phase7.md §17) unless explicitly observed
	Sources        []string
	Confidence     float64
	Documented     bool
	Observed       bool
	Inferred       bool

	FirstSeen time.Time
	LastSeen  time.Time
	Status    Status
	Metadata  map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that e is internally consistent: a non-empty AssetID, a
// recognized method and status, a normalizable URL, and — if set — a valid
// HTTP status code. It performs no network requests; call Normalize first
// and assign its result before validating.
func (e Endpoint) Validate() error {
	var errs validation.Errors

	if e.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if !e.Method.Valid() {
		errs = errs.Add("method", "must be a recognized HTTP method")
	}
	if e.Status != "" && !e.Status.Valid() {
		errs = errs.Add("status", "must be a recognized endpoint status")
	}
	if strings.TrimSpace(e.URL) == "" {
		errs = errs.Add("url", "must not be empty")
	} else if _, err := Normalize(e.URL); err != nil {
		errs = errs.Add("url", err.Error())
	}
	if e.Port != 0 && (e.Port < 1 || e.Port > 65535) {
		errs = errs.Add("port", "must be between 1 and 65535")
	}
	if e.StatusCode != nil && (*e.StatusCode < 100 || *e.StatusCode > 599) {
		errs = errs.Add("status_code", "must be a valid HTTP status code (100-599)")
	}
	if !e.Classification.Valid() {
		errs = errs.Add("classification", "must be a recognized classification")
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}

	return errs.ErrOrNil()
}

// Identity returns the deterministic natural key for an endpoint: method +
// normalized scheme/host/port/path. Two observations of the same method
// against the same normalized URL are the same endpoint, regardless of
// query string or fragment.
func Identity(scheme, host string, port int, path string, method Method) string {
	return string(method) + " " + scheme + "://" + host + ":" + strconv.Itoa(port) + path
}
