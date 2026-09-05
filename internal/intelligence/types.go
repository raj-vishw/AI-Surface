// Package intelligence implements Phase 10's threat-intelligence and risk
// enrichment engine: a self-contained set of Providers that look up
// indicators (domains, IPs, URLs, hostnames, certificates, technologies,
// hashes) and turn the results into normalized, provenance-tagged Record
// values, plus vulnerability matching and (in the risk subpackage) risk
// scoring. Mirroring internal/detection and internal/investigation's split
// (phase8.md §1/phase9.md §1), this package has no dependency on
// internal/domain/intelligence or any database/repository package — a
// Provider takes an in-memory Indicator and returns in-memory Record
// values; internal/service/intelligence is the bridge that resolves
// configuration, assembles Indicators from already-persisted data, calls
// Engine.Lookup, and persists the result (phase10.md §1).
//
// Every Record is exactly one provider's observation. This package never
// collapses multiple providers' observations into a single "confirmed"
// fact — see Aggregate for the read-time, provenance-preserving view, and
// package doc note: a Verdict of "malicious" always means "a provider
// classified this indicator as malicious", never "this platform confirmed
// malicious activity" (phase10.md §18/§98).
package intelligence

import (
	"net"
	"strings"
	"time"
)

// IndicatorType identifies what kind of thing an Indicator's Value
// represents — an independent copy of internal/domain/intelligence.
// IndicatorType's vocabulary, not an import (see package doc comment).
type IndicatorType string

// Recognized indicator types (phase10.md §2).
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

// Indicator is a normalized (Type, Value) pair — the unit every Provider
// looks up and every cache entry keys on.
type Indicator struct {
	Type  IndicatorType
	Value string
}

// Key returns a stable string for map/cache keys.
func (i Indicator) Key() string { return string(i.Type) + "|" + i.Value }

// Verdict is a provider's classification of an indicator. Independent
// copy of internal/domain/intelligence.Verdict — see package doc comment.
type Verdict string

// Recognized verdicts (phase10.md §18).
const (
	VerdictBenign     Verdict = "benign"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
	VerdictUnknown    Verdict = "unknown"
)

// Rank orders verdicts least to most severe.
func (v Verdict) Rank() int {
	switch v {
	case VerdictBenign:
		return 0
	case VerdictSuspicious:
		return 2
	case VerdictMalicious:
		return 3
	default:
		return 1 // unknown/unrecognized
	}
}

// Category classifies the kind of threat a provider associated with an
// indicator. Independent copy of internal/domain/intelligence.Category.
type Category string

// Recognized threat categories (phase10.md §52). Never inferred by this
// engine — only ever set from what a provider actually returned.
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

// Confidence is a leveled (not numeric) confidence rating — see
// internal/domain/intelligence.Confidence's doc comment for why this is
// deliberately not a float (phase10.md §55).
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceUnknown Confidence = "unknown"
	ConfidenceLow     Confidence = "low"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceHigh    Confidence = "high"
)

// Rank orders confidence levels low to high.
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

// ConfidenceFromRank is Rank's inverse, clamped to the recognized range.
func ConfidenceFromRank(rank int) Confidence {
	switch {
	case rank >= 3:
		return ConfidenceHigh
	case rank == 2:
		return ConfidenceMedium
	case rank == 1:
		return ConfidenceLow
	default:
		return ConfidenceUnknown
	}
}

// Capability names one kind of lookup a Provider can perform — used for
// registry introspection/filtering (phase10.md §4/§5).
type Capability string

// Recognized provider capabilities.
const (
	CapabilityLocal         Capability = "local"
	CapabilityDNS           Capability = "dns"
	CapabilityCertificate   Capability = "certificate"
	CapabilityTechnology    Capability = "technology"
	CapabilityVulnerability Capability = "vulnerability"
	CapabilityReputation    Capability = "reputation"
	CapabilityThreatFeed    Capability = "threat_feed"
)

// Record is one provider's normalized observation about one indicator —
// the in-memory counterpart of internal/domain/intelligence.
// Record, produced entirely by a Provider.Lookup call with no
// database access of its own (phase10.md §2/§3).
type Record struct {
	Indicator Indicator

	ProviderID      string
	ProviderVersion string
	SourceType      string // "local", "dns", "certificate", "technology", "vulnerability", "reputation", "threat_feed"

	Category Category
	Verdict  Verdict
	// Confidence is this record's own confidence, as reported (or
	// locally derived) by the single provider that produced it — see
	// AggregatedResult.Confidence for the multi-source combination.
	Confidence Confidence

	FirstSeen   time.Time
	LastSeen    time.Time
	Expiration  *time.Time
	RetrievedAt time.Time

	SourceReference string
	NormalizedData  map[string]any
	Tags            []string
}

// Fresh reports whether r is still within its TTL as of now.
func (r Record) Fresh(now time.Time) bool {
	if r.Expiration == nil {
		return true
	}
	return now.Before(*r.Expiration)
}

// NormalizeDomain canonicalizes a domain/subdomain/hostname value:
// lowercased, trimmed, trailing dot removed.
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

// NormalizeIP canonicalizes an IP address value via net.IP's own
// canonical string form. An unparsable value is returned trimmed but
// otherwise unchanged (phase10.md §56 — never destroy a distinction the
// caller can't be shown to be meaningless).
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}
