// Package intelligence defines the platform's canonical threat-intelligence
// model: normalized, provenance-tagged observations about indicators
// (domains, IPs, URLs, hostnames, certificates, technologies, hashes)
// gathered from local platform data or external providers, plus the
// vulnerability, risk, and enrichment-event records derived from them.
//
// It mirrors internal/domain/finding and internal/domain/investigation's
// shape deliberately — a normalized, evidence-backed record type plus
// small satellite record types (phase10.md §1) — rather than inventing a
// parallel modeling style.
//
// This package holds only the *persisted* representation. The engine that
// produces these values from provider lookups — normalization, provider
// orchestration, aggregation, vulnerability matching, risk scoring — lives
// in internal/intelligence and has no dependency on this package, the same
// way internal/detection has none on internal/domain/finding;
// internal/service/intelligence is the bridge (phase10.md §1).
//
// This package never imports internal/domain/asset, internal/domain/
// finding, or internal/domain/investigation — cross-entity references
// (AssetID, FindingID, InvestigationID) are always a bare uuid.UUID, the
// same "no domain package imports another domain package" discipline
// phase8.md/phase9.md established.
package intelligence

import (
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// IndicatorType identifies what kind of thing an Indicator's Value
// represents (phase10.md §2). Deliberately closed — "do not support
// arbitrary indicator types unless necessary" (phase10.md §2).
type IndicatorType string

// Recognized indicator types.
const (
	IndicatorDomain      IndicatorType = "domain"
	IndicatorSubdomain   IndicatorType = "subdomain"
	IndicatorIPv4        IndicatorType = "ipv4"
	IndicatorIPv6        IndicatorType = "ipv6"
	IndicatorURL         IndicatorType = "url"
	IndicatorHostname    IndicatorType = "hostname"
	IndicatorCertificate IndicatorType = "certificate"
	IndicatorTechnology  IndicatorType = "technology"
	IndicatorHash        IndicatorType = "hash"
)

var validIndicatorTypes = map[IndicatorType]bool{
	IndicatorDomain: true, IndicatorSubdomain: true, IndicatorIPv4: true,
	IndicatorIPv6: true, IndicatorURL: true, IndicatorHostname: true,
	IndicatorCertificate: true, IndicatorTechnology: true, IndicatorHash: true,
}

// Valid reports whether t is a recognized indicator type.
func (t IndicatorType) Valid() bool { return validIndicatorTypes[t] }

// Indicator is a normalized (Type, Value) pair identifying the thing
// intelligence is being gathered about.
type Indicator struct {
	Type  IndicatorType
	Value string
}

// Validate checks that i is internally consistent.
func (i Indicator) Validate() error {
	var errs validation.Errors
	if !i.Type.Valid() {
		errs = errs.Add("type", "must be a recognized indicator type")
	}
	if strings.TrimSpace(i.Value) == "" {
		errs = errs.Add("value", "must not be empty")
	}
	return errs.ErrOrNil()
}

// Key returns a stable string suitable for map keys / cache keys —
// "type|value".
func (i Indicator) Key() string { return string(i.Type) + "|" + i.Value }

// Verdict is a provider's classification of an indicator (phase10.md
// §18). IMPORTANT: a Verdict of Malicious means "the provider classified
// this indicator as malicious" — it is never presented as confirmed
// malicious activity observed by this platform (phase10.md §18/§98).
type Verdict string

// Recognized verdicts.
const (
	VerdictBenign     Verdict = "benign"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
	VerdictUnknown    Verdict = "unknown"
)

var validVerdicts = map[Verdict]bool{
	VerdictBenign: true, VerdictSuspicious: true, VerdictMalicious: true, VerdictUnknown: true,
}

// Valid reports whether v is a recognized verdict.
func (v Verdict) Valid() bool { return validVerdicts[v] }

// Rank orders verdicts from least to most severe, for aggregation
// (phase10.md §20).
func (v Verdict) Rank() int {
	switch v {
	case VerdictBenign:
		return 0
	case VerdictUnknown:
		return 1
	case VerdictSuspicious:
		return 2
	case VerdictMalicious:
		return 3
	default:
		return 1
	}
}

// Category classifies the kind of threat a provider associated with an
// indicator (phase10.md §52). Empty means the provider gave no category.
// Never inferred by this platform from an indicator alone (phase10.md
// §52 — "do not infer malware family from an IP alone").
type Category string

// Recognized threat categories.
const (
	CategoryMalware         Category = "malware"
	CategoryPhishing        Category = "phishing"
	CategoryBotnet          Category = "botnet"
	CategoryScanner         Category = "scanner"
	CategorySpam            Category = "spam"
	CategorySuspicious      Category = "suspicious"
	CategoryExploit         Category = "exploit"
	CategoryCredentialAbuse Category = "credential_abuse" //nolint:gosec // this is a threat-category label, not a credential value
)

var validCategories = map[Category]bool{
	CategoryMalware: true, CategoryPhishing: true, CategoryBotnet: true,
	CategoryScanner: true, CategorySpam: true, CategorySuspicious: true,
	CategoryExploit: true, CategoryCredentialAbuse: true,
}

// Valid reports whether c is a recognized category, or empty (no
// category given).
func (c Category) Valid() bool { return c == "" || validCategories[c] }

// Confidence is a leveled (not numeric) confidence rating. Intelligence
// confidence is deliberately kept as a small, named vocabulary rather
// than a float — this project does not claim mathematically calibrated
// probability for provider-reported or aggregated confidence
// (phase10.md §55: "do not pretend this is mathematically calibrated
// unless it is").
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceUnknown Confidence = "unknown"
	ConfidenceLow     Confidence = "low"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceHigh    Confidence = "high"
)

var validConfidences = map[Confidence]bool{
	ConfidenceUnknown: true, ConfidenceLow: true, ConfidenceMedium: true, ConfidenceHigh: true,
}

// Valid reports whether c is a recognized confidence level.
func (c Confidence) Valid() bool { return validConfidences[c] }

// Rank orders confidence levels low to high, for aggregation/comparison.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Record is one provider's normalized observation about one
// indicator — the atomic, provenance-tagged unit this package persists
// (phase10.md §2/§3). Multiple records commonly exist for the same
// indicator (one per provider that has looked it up); they are never
// merged into a single row — see internal/intelligence.Aggregate for the
// read-time aggregation view that preserves every source (phase10.md
// §19/§47).
type Record struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	IndicatorType  IndicatorType
	IndicatorValue string

	// ProviderID/ProviderVersion identify exactly which provider, and
	// which version of it, produced this record (phase10.md §6) — so a
	// historical record remains interpretable even after the provider's
	// behavior changes.
	ProviderID      string
	ProviderVersion string
	// SourceType classifies the provider's kind: "local", "dns",
	// "certificate", "vulnerability", "reputation", "threat_feed" — used
	// for filtering/display without a provider registry lookup.
	SourceType string

	Category Category
	Verdict  Verdict
	// Confidence is exactly the confidence for THIS record — see
	// internal/intelligence.AggregatedResult.Confidence for the combined
	// multi-source confidence.
	Confidence Confidence

	FirstSeen time.Time
	LastSeen  time.Time
	// Expiration is when this record's TTL elapses and it should no
	// longer be treated as fresh (phase10.md §22) — nil means "does not
	// expire". Expired records are never deleted (phase10.md §47:
	// preserve history) — see internal/intelligence.Fresh.
	Expiration  *time.Time
	RetrievedAt time.Time

	// SourceReference is a provider-specific pointer back to where this
	// observation came from (a feed entry id, a certificate serial, ...)
	// — never a credential or secret (phase10.md §67).
	SourceReference string
	// NormalizedData carries the record's normalized payload (DNS record
	// values, certificate fields, technology product/vendor/version, ...)
	// — sanitized before storage exactly like asset.Metadata/finding.
	// Metadata (phase10.md §68: external content is untrusted data,
	// never executed or rendered as HTML).
	NormalizedData map[string]any

	// Tags are provider-derived labels ("known-malicious", "scanner")
	// distinct from any future analyst-applied tag (phase10.md §53).
	Tags []string

	CreatedAt time.Time
	UpdatedAt time.Time
}

var validSourceTypes = map[string]bool{
	"local": true, "dns": true, "certificate": true, "technology": true,
	"vulnerability": true, "reputation": true, "threat_feed": true,
}

// Validate checks that r is internally consistent.
func (r Record) Validate() error {
	var errs validation.Errors

	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !r.IndicatorType.Valid() {
		errs = errs.Add("indicator_type", "must be a recognized indicator type")
	}
	if strings.TrimSpace(r.IndicatorValue) == "" {
		errs = errs.Add("indicator_value", "must not be empty")
	}
	if strings.TrimSpace(r.ProviderID) == "" {
		errs = errs.Add("provider_id", "must not be empty")
	}
	if !validSourceTypes[r.SourceType] {
		errs = errs.Add("source_type", "must be a recognized provider source type")
	}
	if !r.Category.Valid() {
		errs = errs.Add("category", "must be a recognized category or empty")
	}
	if !r.Verdict.Valid() {
		errs = errs.Add("verdict", "must be a recognized verdict")
	}
	if !r.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if r.RetrievedAt.IsZero() {
		errs = errs.Add("retrieved_at", "must not be zero")
	}

	return errs.ErrOrNil()
}

// Fresh reports whether r is still within its TTL as of now.
func (r Record) Fresh(now time.Time) bool {
	if r.Expiration == nil {
		return true
	}
	return now.Before(*r.Expiration)
}

// NormalizeDomain canonicalizes a domain/subdomain/hostname indicator
// value: lowercased and trimmed, trailing dot removed. It never removes
// meaningful structure (phase10.md §56).
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

// NormalizeIP canonicalizes an IP address indicator value via net.IP's
// own canonical string form (e.g. leading zeros / IPv6 shorthand
// normalized) — an invalid address is returned trimmed but otherwise
// unchanged, since canonicalization only applies to a value it can
// actually parse.
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
