package fingerprint

// SignalRule is one declarative condition within a Signature — "the
// Server header matches ^nginx, weight 0.90" (phase6.md §6). The schema
// is intentionally small and uniform across every SignalType rather than
// a different shape per type, so the loader/validator/matcher each have
// exactly one code path, not one per technology (phase6.md §6's "avoid a
// giant hardcoded switch statement").
type SignalRule struct {
	// Type selects what Observation field(s) this rule inspects — see
	// SignalType.
	Type SignalType `yaml:"type"`
	// Field names what within Type to inspect: a header name
	// (http_header/rate_limit_header/response_header), a cookie name
	// (cookie_name), a DNS record type (dns_record — "A", "CNAME", ...;
	// unused for dns_cname, which always inspects the CNAME chain), a
	// JSON key (json_structure). Not every type uses Field — content_type,
	// html, url_path, api_path, error_message, response_hash, tls,
	// service, and port match against a single well-known observation
	// field and leave Field empty.
	Field string `yaml:"field,omitempty"`
	// Pattern is a Go regexp (RE2 — no catastrophic-backtracking
	// constructs are possible, phase6.md §29) matched against the
	// selected field's value. Required for every type except "service"
	// and "port", which may instead use Equals for an exact match.
	Pattern string `yaml:"pattern,omitempty"`
	// Equals, when set, requires an exact (case-insensitive) match
	// instead of a regex — the simplest, safest option for signal types
	// like service/port where the value is already a known enum/number.
	Equals string `yaml:"equals,omitempty"`
	// Weight is this signal's contribution toward the signature's score,
	// in (0.0, 1.0] (phase6.md §8).
	Weight float64 `yaml:"weight"`
	// VersionGroup, if > 0, names a 1-indexed capture group in Pattern
	// whose match is the technology's version string (phase6.md §12) —
	// never inferred any other way.
	VersionGroup int `yaml:"version_group,omitempty"`
	// Required marks a signal that must match for the signature to match
	// at all, regardless of how much weight other optional signals
	// contribute (phase6.md §32's "required signals").
	Required bool `yaml:"required,omitempty"`
}

// Signature is one declarative technology-detection rule, loaded from
// YAML (phase6.md §6) — the alternative to a hardcoded switch statement.
// A Signature matches an Observation when every Required signal matches
// (if any are declared) and at least one signal matches overall; its
// Score is then computed from the matched signals' weights (see
// scorer.go).
type Signature struct {
	// Name is the signature's stable identifier and the fingerprint's
	// Technology value on a match (before normalization — see
	// normalizer.go). Must be unique across every loaded signature file.
	Name string `yaml:"name"`
	// Category classifies the technology this signature identifies.
	Category Category `yaml:"category"`
	Vendor   string   `yaml:"vendor,omitempty"`
	Product  string   `yaml:"product,omitempty"`

	Signals []SignalRule `yaml:"signals"`
	// NegativeSignals: if any matches, this signature is disqualified
	// entirely (phase6.md §10's conflict handling; §32's "negative
	// signals") — e.g. an nginx signature can declare a negative signal
	// for an unambiguous Apache marker, so a response carrying both
	// headers (a misconfigured proxy, say) doesn't score nginx as if the
	// Apache evidence didn't exist.
	NegativeSignals []SignalRule `yaml:"negative_signals,omitempty"`

	// MinScore overrides the engine's default minimum-confidence filter
	// for this signature specifically (phase6.md §32's "minimum score");
	// 0 means "use the engine's configured default".
	MinScore float64 `yaml:"min_score,omitempty"`

	// IncompatibleWith names other signature Names this one is mutually
	// exclusive with by explicit declaration (phase6.md §10: "the engine
	// must NOT assume one fingerprint excludes another unless the
	// signature explicitly declares incompatibility"). When two mutually
	// incompatible signatures both match, the lower-scoring one is
	// dropped rather than both being reported as if they coexisted.
	IncompatibleWith []string `yaml:"incompatible_with,omitempty"`
}
