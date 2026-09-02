package fingerprint

import "time"

// DNSRecordObservation is one DNS record already collected by Phase 5,
// carried into an Observation for signature matching (dns_cname/
// dns_record signal types).
type DNSRecordObservation struct {
	Type  string // "A", "AAAA", "CNAME", "NS", "MX", "TXT", ...
	Value string
}

// Observation is everything the matcher may inspect for one asset,
// assembled entirely from data already persisted by Phase 3/4/5 (HTTP
// headers/content-type/status/cookies, DNS records, port/service
// classification, TLS metadata) — never fetched fresh (phase6.md §46).
// Fields with no current data source (HTML, Scripts, Stylesheets,
// JSONKeys, ExplicitModel) are included for schema completeness and
// exercised by synthetic test fixtures; see docs/architecture/
// fingerprinting.md's "Known Limitations" for exactly which signal types
// have no real backing data yet and why (Phase 3 deliberately never
// retains HTTP response bodies).
type Observation struct {
	AssetID  string
	Hostname string
	URL      string
	URLPath  string

	// Headers holds a curated, already-redacted subset of response
	// headers — safe metadata only, never Authorization/Cookie/secret
	// values (phase6.md §13/§31). Keys are canonical (net/http.
	// CanonicalHeaderKey form, e.g. "X-Powered-By").
	Headers map[string]string
	// CookieNames holds Set-Cookie cookie *names* only — never values
	// (phase6.md §13/§31).
	CookieNames  []string
	ContentType  string
	StatusCode   *int
	ResponseHash string

	// Service is Phase 4's port-classification result (e.g. "HTTP",
	// "DATABASE", "SSH") when this observation represents a PORT/SERVICE
	// asset.
	Service string
	Port    *int

	TLSVersion         string
	TLSCipherSuite     string
	CertificateSubject string
	CertificateIssuer  string

	DNSRecords []DNSRecordObservation

	// APIPaths holds every distinct discovered endpoint path for this
	// asset/target (from Phase 3's Endpoint rows) — used for api_path/
	// url_path signal matching (REST/GraphQL/OpenAPI/Swagger detection).
	APIPaths []string

	// HTML/Scripts/Stylesheets/JSONKeys/ExplicitModel: reserved for a
	// future phase that retains response-body snippets. Always empty
	// from real persisted data today (see the package doc comment) —
	// populated only by synthetic test fixtures that exercise the
	// matcher's html/html_meta/script/stylesheet/json_structure signal
	// handling directly, independent of what's currently wired to real
	// evidence.
	HTML          string
	Scripts       []string
	Stylesheets   []string
	JSONKeys      []string
	ExplicitModel string
	ErrorMessage  string

	ObservedAt time.Time
}

// HeaderValue looks up a header case-insensitively-normalized already
// (Headers keys are stored in canonical form), returning "" if absent.
func (o Observation) HeaderValue(name string) string {
	return o.Headers[name]
}
