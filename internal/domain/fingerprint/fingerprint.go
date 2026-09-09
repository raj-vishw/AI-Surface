// Package fingerprint defines the platform's canonical technology
// fingerprint model: a normalized belief ("this asset appears to run
// nginx") derived from passive analysis of evidence Phase 3/4/5 already
// collected, plus the append-only evidence trail that justifies it. It
// mirrors internal/domain/asset and internal/domain/endpoint's shape
// deliberately (Fingerprint/Signal here play the same roles Asset/
// Evidence do there) rather than inventing a parallel modeling style.
//
// This package holds only the *persisted* representation. The engine that
// produces Fingerprint/Signal values from raw observations —
// signature matching, scoring, normalization — lives in
// internal/fingerprint and has no dependency on this package, the same
// way internal/discovery/dns has no dependency on internal/domain/asset;
// internal/service/fingerprint is the bridge, exactly as
// internal/discovery/service is for discovery (phase6.md §47).
package fingerprint

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Category classifies what kind of thing a fingerprint identifies.
// Distinct from asset.Type (which classifies discovered *things*) — a
// single HTTP_ENDPOINT asset can carry fingerprints in several categories
// at once (web_server, framework, frontend, runtime), which is exactly
// why fingerprints are their own entity rather than more Asset fields
// (phase6.md §4).
type Category string

// Recognized fingerprint categories (phase6.md §4).
const (
	CategoryWebServer        Category = "web_server"
	CategoryReverseProxy     Category = "reverse_proxy"
	CategoryFramework        Category = "framework"
	CategoryFrontend         Category = "frontend"
	CategoryRuntime          Category = "runtime"
	CategoryProgrammingLang  Category = "programming_language"
	CategoryCMS              Category = "cms"
	CategoryAPI              Category = "api"
	CategoryCloud            Category = "cloud"
	CategoryCDN              Category = "cdn"
	CategoryDatabase         Category = "database"
	CategoryAuthentication   Category = "authentication"
	CategoryMonitoring       Category = "monitoring"
	CategoryAnalytics        Category = "analytics"
	CategoryAIProvider       Category = "ai_provider"
	CategoryAIPlatform       Category = "ai_platform"
	CategoryAIModelCandidate Category = "ai_model_candidate"
	CategoryService          Category = "service"
	CategoryLibrary          Category = "library"
	CategoryInfrastructure   Category = "infrastructure"
)

var validCategories = map[Category]bool{
	CategoryWebServer: true, CategoryReverseProxy: true, CategoryFramework: true,
	CategoryFrontend: true, CategoryRuntime: true, CategoryProgrammingLang: true,
	CategoryCMS: true, CategoryAPI: true, CategoryCloud: true, CategoryCDN: true,
	CategoryDatabase: true, CategoryAuthentication: true, CategoryMonitoring: true,
	CategoryAnalytics: true, CategoryAIProvider: true, CategoryAIPlatform: true,
	CategoryAIModelCandidate: true, CategoryService: true, CategoryLibrary: true,
	CategoryInfrastructure: true,
}

// Valid reports whether c is a recognized fingerprint category.
func (c Category) Valid() bool { return validCategories[c] }

// Status tracks whether a fingerprint's identity is still being observed
// as of the most recent analysis run against its asset, mirroring
// asset.Status's ACTIVE/INACTIVE vocabulary for the same reason
// domainendpoint.Status does: a fingerprint that stops matching is never
// deleted (phase6.md §22 — "do not delete historical observations"), it
// moves to INACTIVE while its row, FirstSeen, and full evidence trail are
// preserved untouched.
type Status string

// Recognized fingerprint statuses.
const (
	StatusActive   Status = "ACTIVE"
	StatusInactive Status = "INACTIVE"
)

var validStatuses = map[Status]bool{StatusActive: true, StatusInactive: true}

// Valid reports whether s is a recognized fingerprint status.
func (s Status) Valid() bool { return validStatuses[s] }

// Score is a fingerprint's confidence, in [0.0, 1.0]. It is a distinct
// type from asset.Confidence — deliberately, the same reasoning
// domainendpoint.Status is kept distinct from domainasset.Status for:
// this package has no dependency on internal/domain/asset, and the two
// numbers answer different questions. asset.Confidence expresses "how
// sure are we this asset exists"; Score expresses "how strong is the
// combined evidence for this specific technology claim" — fingerprint
// evidence strength, never a statistical probability (phase6.md §8).
type Score float64

// Score level boundaries (phase6.md §8) — configurable via
// internal/fingerprint.Thresholds for the engine that computes Score
// values; these are the fixed default bucketing applied here for display/
// filtering once a Score is already computed and persisted.
const (
	thresholdLow      = 0.30
	thresholdMedium   = 0.60
	thresholdHigh     = 0.80
	thresholdVeryHigh = 0.95
)

// Level names a bucketed Score.
type Level string

// Recognized score levels, weak to very_high (phase6.md §8).
const (
	LevelWeak     Level = "weak"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelVeryHigh Level = "very_high"
)

// Validate reports whether s falls within the valid [0.0, 1.0] range.
func (s Score) Validate() error {
	if s < 0.0 || s > 1.0 {
		var errs validation.Errors
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
		return errs.ErrOrNil()
	}
	return nil
}

// Level buckets s into a named level using the default thresholds.
func (s Score) Level() Level {
	switch {
	case s >= thresholdVeryHigh:
		return LevelVeryHigh
	case s >= thresholdHigh:
		return LevelHigh
	case s >= thresholdMedium:
		return LevelMedium
	case s >= thresholdLow:
		return LevelLow
	default:
		return LevelWeak
	}
}

// Fingerprint is one normalized technology belief about an asset —
// "this asset appears to run nginx, category web_server, confidence
// 0.91" — backed by the Signal evidence trail (see evidence.go). Multiple
// Fingerprint rows commonly coexist for one asset (phase6.md §4): nginx,
// Next.js, React, Node.js, and Cloudflare can all be true simultaneously
// for the same HTTP_ENDPOINT asset.
type Fingerprint struct {
	ID       uuid.UUID
	AssetID  uuid.UUID
	TargetID uuid.UUID
	// ScanID is the most recent scan that (re-)confirmed this
	// fingerprint. Unlike asset_evidence's evidence rows, a Fingerprint
	// is a mutable "current state" row (see Status) — ScanID always
	// reflects the latest analysis, not the first.
	ScanID *uuid.UUID

	Category   Category
	Technology string // normalized technology identity, e.g. "nginx", "Next.js"
	Product    string // human-facing product name, when distinct from Technology; often equal to it
	Vendor     string // e.g. "F5" for nginx, "Vercel" for Next.js; "" if unknown
	Version    string // "" (never guessed) unless explicitly extracted from evidence — see internal/fingerprint's version extraction

	Confidence Score
	Status     Status

	// Metadata carries the latest matched-signal snapshot for quick
	// display without a join — the same "latest snapshot, full history
	// lives in evidence" split Phase 5 established for DNS records (see
	// docs/architecture/dns-discovery.md). It is sanitized before storage
	// exactly like asset.Metadata.
	Metadata map[string]any

	FirstSeen time.Time
	LastSeen  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that f is internally consistent.
func (f Fingerprint) Validate() error {
	var errs validation.Errors

	if f.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if f.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !f.Category.Valid() {
		errs = errs.Add("category", "must be a recognized fingerprint category")
	}
	if strings.TrimSpace(f.Technology) == "" {
		errs = errs.Add("technology", "must not be empty")
	}
	if f.Status != "" && !f.Status.Valid() {
		errs = errs.Add("status", "must be a recognized fingerprint status")
	}
	if err := f.Confidence.Validate(); err != nil {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}

	return errs.ErrOrNil()
}

// IdentityKey returns the deterministic natural key for a fingerprint:
// one asset can have at most one *current* fingerprint per (category,
// normalized technology) pair — re-observing "nginx, web_server" again
// updates the existing row (LastSeen advances, Status stays/returns to
// ACTIVE) rather than creating a duplicate, mirroring asset.Identity's
// per-type natural keys.
func IdentityKey(assetID uuid.UUID, category Category, technology string) string {
	return assetID.String() + "|" + string(category) + "|" + strings.ToLower(strings.TrimSpace(technology))
}
