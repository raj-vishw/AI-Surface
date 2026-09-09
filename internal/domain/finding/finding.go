// Package finding defines the platform's canonical security-finding model:
// a normalized, evidence-backed belief that a specific asset or endpoint
// exhibits a security-relevant condition — "example.com is missing
// Content-Security-Policy" — derived by internal/detection from evidence
// Phase 2-7 already collected and persisted, plus the append-only evidence
// and lifecycle-event trail that justify and track it.
//
// It mirrors internal/domain/asset, internal/domain/endpoint, and
// internal/domain/fingerprint's shape deliberately (Finding/Evidence/Event
// here play the same roles Asset/Evidence, Endpoint/Evidence, and
// Fingerprint/Evidence do there) rather than inventing a parallel modeling
// style (phase8.md §2).
//
// This package holds only the *persisted* representation. The engine that
// produces Finding values from raw observations — detector logic, severity/
// confidence rules, deduplication — lives in internal/detection and has no
// dependency on this package, the same way internal/fingerprint has none on
// internal/domain/fingerprint; internal/service/detection is the bridge
// (phase8.md §1).
package finding

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Category classifies what kind of security condition a Finding
// represents (phase8.md §46). Deliberately coarse and closed — a detector
// that doesn't fit one of these honestly is a sign the category list needs
// to grow, not that a finding should be forced into the wrong bucket.
type Category string

// Recognized finding categories.
const (
	CategoryConfiguration         Category = "configuration"
	CategoryAuthentication        Category = "authentication"
	CategoryAuthorization         Category = "authorization"
	CategoryCryptography          Category = "cryptography"
	CategoryInformationDisclosure Category = "information_disclosure"
	CategoryExposure              Category = "exposure"
	CategoryAPI                   Category = "api"
	CategoryWeb                   Category = "web"
	CategoryInfrastructure        Category = "infrastructure"
	CategoryTechnology            Category = "technology"
	CategoryCertificate           Category = "certificate"
	CategorySecurityHeaders       Category = "security_headers"
)

var validCategories = map[Category]bool{
	CategoryConfiguration: true, CategoryAuthentication: true, CategoryAuthorization: true,
	CategoryCryptography: true, CategoryInformationDisclosure: true, CategoryExposure: true,
	CategoryAPI: true, CategoryWeb: true, CategoryInfrastructure: true, CategoryTechnology: true,
	CategoryCertificate: true, CategorySecurityHeaders: true,
}

// Valid reports whether c is a recognized finding category.
func (c Category) Valid() bool { return validCategories[c] }

// Severity answers "how serious could this issue be?" — a property of the
// condition itself, independent of how sure the detector is that the
// condition is actually present (see Confidence, which answers that
// separate question — phase8.md §12/§57: the two are never mixed).
type Severity string

// Recognized severities, informational to critical.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInformational: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Valid reports whether s is a recognized severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank returns s's ordinal position (0 = informational, 4 = critical),
// for sorting and threshold comparisons. An unrecognized severity ranks
// below informational (-1) rather than panicking.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// Confidence answers "how confident are we that this finding is actually
// present?" — in [0.0, 1.0]. A distinct type from asset.Confidence and
// fingerprint.Score for the same reason those are kept distinct from each
// other: this package has no dependency on internal/domain/asset or
// internal/domain/fingerprint, and the three numbers answer different
// questions (phase8.md §12).
type Confidence float64

// Confidence level boundaries (phase8.md §12's five-bucket model).
const (
	thresholdLow      = 0.20
	thresholdMedium   = 0.45
	thresholdHigh     = 0.70
	thresholdVeryHigh = 0.90
)

// Level names a bucketed Confidence value.
type Level string

// Recognized confidence levels, very_low to very_high.
const (
	LevelVeryLow  Level = "very_low"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelVeryHigh Level = "very_high"
)

// Validate reports whether c falls within the valid [0.0, 1.0] range.
func (c Confidence) Validate() error {
	if c < 0.0 || c > 1.0 {
		var errs validation.Errors
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
		return errs.ErrOrNil()
	}
	return nil
}

// Level buckets c into a named confidence level.
func (c Confidence) Level() Level {
	switch {
	case c < 0 || c > 1:
		return LevelVeryLow
	case c >= thresholdVeryHigh:
		return LevelVeryHigh
	case c >= thresholdHigh:
		return LevelHigh
	case c >= thresholdMedium:
		return LevelMedium
	case c >= thresholdLow:
		return LevelLow
	default:
		return LevelVeryLow
	}
}

// Scope names the granularity a Finding's identity is computed at
// (phase8.md §45). EndpointID is populated if and only if scope is
// ScopeEndpoint.
type Scope string

// Recognized finding scopes.
const (
	ScopeAsset    Scope = "asset"
	ScopeEndpoint Scope = "endpoint"
	ScopeTarget   Scope = "target"
)

var validScopes = map[Scope]bool{ScopeAsset: true, ScopeEndpoint: true, ScopeTarget: true}

// Valid reports whether s is a recognized finding scope.
func (s Scope) Valid() bool { return validScopes[s] }

// Status tracks a Finding's lifecycle state (phase8.md §4). A Finding row
// is never deleted when a condition stops being observed — Status moves to
// StatusResolved instead, and can move back to StatusReopened if the
// condition returns; the full history of that movement is recorded as
// append-only Event rows (see event.go), not reconstructed from Status
// alone.
type Status string

// Recognized finding statuses.
const (
	StatusOpen          Status = "open"
	StatusResolved      Status = "resolved"
	StatusReopened      Status = "reopened"
	StatusAcceptedRisk  Status = "accepted_risk"
	StatusFalsePositive Status = "false_positive"
)

var validStatuses = map[Status]bool{
	StatusOpen: true, StatusResolved: true, StatusReopened: true,
	StatusAcceptedRisk: true, StatusFalsePositive: true,
}

// Valid reports whether s is a recognized finding status.
func (s Status) Valid() bool { return validStatuses[s] }

// Open reports whether s represents a currently-actionable state (open or
// reopened) as opposed to resolved or suppressed (accepted_risk/
// false_positive).
func (s Status) Open() bool { return s == StatusOpen || s == StatusReopened }

// Reference is a stable, external pointer supporting a Finding —
// never invented (phase8.md §49): only identifiers/URLs the detector
// actually knows to be correct (an RFC number, an OWASP category slug, an
// MDN page) are ever populated.
type Reference struct {
	Label string // e.g. "OWASP", "MDN", "RFC 6797"
	URL   string
}

// Finding is one normalized, evidence-backed security observation about an
// asset or endpoint. Fields already represented on Asset or Endpoint
// (hostname, URL, technology, ...) are deliberately not duplicated here —
// callers join through AssetID/EndpointID (phase8.md §2).
type Finding struct {
	ID         uuid.UUID
	TargetID   uuid.UUID
	AssetID    uuid.UUID
	EndpointID *uuid.UUID
	// ScanID is the most recent scan that (re-)confirmed this finding.
	// Unlike finding_evidence's rows, a Finding is a mutable "current
	// state" row — ScanID always reflects the latest detection run, not
	// the first (mirrors fingerprint.Fingerprint.ScanID).
	ScanID *uuid.UUID

	DetectorID      string
	DetectorVersion int
	Title           string
	Description     string

	Category Category
	Scope    Scope

	// Severity is the *effective* severity: DetectorSeverity unless a
	// human has overridden it (see SeverityOverridden/-Reason/-At below).
	// A re-run never destroys the override — see phase8.md §79.
	Severity Severity
	// DetectorSeverity is always exactly what the detector most recently
	// computed, regardless of any override — preserved so an override is
	// never confused with a change in the underlying condition.
	DetectorSeverity Severity
	Confidence       Confidence

	Status Status

	IdentityKey string

	Remediation string
	References  []Reference

	// Metadata carries the latest evidence snapshot for quick display
	// without a join — the same "latest snapshot, full history lives in
	// evidence" split Phase 5/6/7 all use. It is sanitized before storage
	// exactly like asset.Metadata.
	Metadata map[string]any

	SeverityOverridden     bool
	SeverityOverrideReason string
	SeverityOverriddenAt   *time.Time

	// SuppressionReason explains why Status is accepted_risk or
	// false_positive — required whenever one of those statuses is set
	// (phase8.md §77).
	SuppressionReason string

	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that f is internally consistent.
func (f Finding) Validate() error {
	var errs validation.Errors

	if f.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if f.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if strings.TrimSpace(f.DetectorID) == "" {
		errs = errs.Add("detector_id", "must not be empty")
	}
	if strings.TrimSpace(f.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !f.Category.Valid() {
		errs = errs.Add("category", "must be a recognized finding category")
	}
	if !f.Scope.Valid() {
		errs = errs.Add("scope", "must be a recognized finding scope")
	}
	if f.Scope == ScopeEndpoint && f.EndpointID == nil {
		errs = errs.Add("endpoint_id", "must be set when scope is endpoint")
	}
	if f.Scope != ScopeEndpoint && f.EndpointID != nil {
		errs = errs.Add("endpoint_id", "must be empty unless scope is endpoint")
	}
	if !f.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !f.DetectorSeverity.Valid() {
		errs = errs.Add("detector_severity", "must be a recognized severity")
	}
	if err := f.Confidence.Validate(); err != nil {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}
	if !f.Status.Valid() {
		errs = errs.Add("status", "must be a recognized finding status")
	}
	if (f.Status == StatusAcceptedRisk || f.Status == StatusFalsePositive) && strings.TrimSpace(f.SuppressionReason) == "" {
		errs = errs.Add("suppression_reason", "must not be empty when status is accepted_risk or false_positive")
	}
	if strings.TrimSpace(f.IdentityKey) == "" {
		errs = errs.Add("identity_key", "must not be empty")
	}

	return errs.ErrOrNil()
}

// IdentityKey returns the deterministic natural key for a finding
// (phase8.md §3): never a timestamp, random UUID, or scan id. It is scoped
// by targetID/assetID/detectorID always, plus endpointID when scope is
// ScopeEndpoint — so "Missing HSTS on https://example.com" is the same
// logical finding across every scan, while the same detector firing on two
// distinct endpoints of the same asset produces two distinct findings (not
// a duplicate — phase8.md §44).
func IdentityKey(targetID, assetID uuid.UUID, endpointID *uuid.UUID, detectorID string) string {
	key := targetID.String() + "|" + assetID.String() + "|" + detectorID
	if endpointID != nil {
		key += "|" + endpointID.String()
	}
	return key
}
