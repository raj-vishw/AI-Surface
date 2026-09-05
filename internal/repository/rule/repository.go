// Package rule implements persistence for the rule domain model —
// mirroring internal/repository/investigation's shape and conventions
// exactly (one PostgresRepository type implementing several narrow,
// entity-specific interfaces). It never imports internal/ruleengine (the
// engine) — a RuleVersion's Definition is stored and returned as an
// opaque string (already-canonical JSON produced by
// internal/ruleengine.EncodeJSON), so this package has no dependency on
// the engine package, the same engine/repository boundary
// internal/repository/finding keeps with internal/detection.
package rule

import (
	"context"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/rule"
	"ai-recon-platform/internal/repository/pagination"
)

// ListFilter narrows a rule listing. Zero-valued fields are not
// applied.
type ListFilter struct {
	TargetID   uuid.UUID
	Status     rule.Status
	RuleType   rule.Type
	Category   string
	Pagination pagination.Params
}

// Repository persists and queries Rule rows. A Rule's Definition
// never lives here — see VersionRepository (phase11.md §4/§61).
type Repository interface {
	CreateRule(ctx context.Context, r rule.Rule) (rule.Rule, error)
	GetRuleByID(ctx context.Context, id uuid.UUID) (rule.Rule, error)
	// GetByName returns the rule named name within targetID, or a
	// errors.CategoryNotFound error if none exists — rule names are
	// unique per target (phase11.md §3's worked "suspicious_login_
	// pattern" example implies a stable, addressable name).
	GetByName(ctx context.Context, targetID uuid.UUID, name string) (rule.Rule, error)
	ListRules(ctx context.Context, filter ListFilter) (pagination.Page[rule.Rule], error)
	// UpdateMetadata updates a rule's editable metadata (description,
	// category, tags, references, documentation URL, updated_by) —
	// never Name (the stable identity) and never Severity/RuleType
	// directly (those always flow from the latest RuleVersion via
	// SyncSeverityFromVersion, so they can never drift from the actual
	// evaluated logic — see that method's doc comment).
	UpdateMetadata(ctx context.Context, id uuid.UUID, description, category string, tags, references []string, documentationURL, updatedBy string) (rule.Rule, error)
	// UpdateStatus transitions a rule's lifecycle status (phase11.md
	// §30/§31) — never deletes the row (phase11.md §3: "do not delete
	// historical rules").
	UpdateRuleStatus(ctx context.Context, id uuid.UUID, status rule.Status, updatedBy string) (rule.Rule, error)
	// SyncSeverityFromVersion updates a rule's denormalized Severity/
	// Confidence/RuleType display fields to mirror its latest version's
	// Definition — called by VersionRepository.Create's caller
	// immediately after creating a new version, so Rule never carries a
	// Severity/Confidence that could contradict what its current logic
	// actually produces.
	SyncSeverityFromVersion(ctx context.Context, id uuid.UUID, severity rule.Severity, confidence rule.Confidence, ruleType rule.Type) (rule.Rule, error)
}

// VersionRepository persists and queries RuleVersion rows. Create is
// the only way a version's Definition is ever written — there is no
// Update (phase11.md §5: immutable once created). SetEnabled is the one
// permitted mutation, and it never touches Definition/DefinitionHash.
type VersionRepository interface {
	// Create inserts v with the next sequential version number for
	// v.RuleID (phase11.md §4) — the caller must not set v.Version.
	CreateVersion(ctx context.Context, v rule.Version) (rule.Version, error)
	GetVersionByID(ctx context.Context, id uuid.UUID) (rule.Version, error)
	GetByRuleAndVersion(ctx context.Context, ruleID uuid.UUID, version int) (rule.Version, error)
	// GetLatest returns ruleID's highest-numbered version, regardless of
	// Enabled.
	GetLatest(ctx context.Context, ruleID uuid.UUID) (rule.Version, error)
	// GetLatestEnabled returns ruleID's highest-numbered version with
	// Enabled = true, or a errors.CategoryNotFound error if none exists
	// (phase11.md §31: a disabled rule/version produces no new matches).
	GetLatestEnabled(ctx context.Context, ruleID uuid.UUID) (rule.Version, error)
	ListVersions(ctx context.Context, ruleID uuid.UUID) ([]rule.Version, error)
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) (rule.Version, error)
}

// MatchListFilter narrows a detection-match listing.
type MatchListFilter struct {
	TargetID   uuid.UUID
	RuleID     uuid.UUID
	Status     rule.MatchStatus
	Pagination pagination.Params
}

// MatchRepository persists and queries DetectionMatch rows.
type MatchRepository interface {
	// Upsert inserts m, or — if a row with the same Fingerprint already
	// exists — widens LastObservedAt to the later of the two timestamps
	// (phase11.md §33's deduplication) without touching Status: an
	// analyst's acknowledged/resolved/suppressed decision on an existing
	// match is never silently reverted by a later re-observation of the
	// same underlying pattern. created reports whether a new row was
	// inserted.
	UpsertMatch(ctx context.Context, m rule.DetectionMatch) (result rule.DetectionMatch, created bool, err error)
	GetMatchByID(ctx context.Context, id uuid.UUID) (rule.DetectionMatch, error)
	ListMatches(ctx context.Context, filter MatchListFilter) (pagination.Page[rule.DetectionMatch], error)
	UpdateMatchStatus(ctx context.Context, id uuid.UUID, status rule.MatchStatus) (rule.DetectionMatch, error)
}

// EvidenceRepository persists and queries append-only MatchEvidence
// rows.
type EvidenceRepository interface {
	// AttachEvidence inserts e. If a row with the same
	// (detection_match_id, source_type, source_id, role) already exists,
	// this is a deduplicating no-op — the existing row is returned
	// unchanged and created is false.
	AttachEvidence(ctx context.Context, e rule.MatchEvidence) (result rule.MatchEvidence, created bool, err error)
	ListByMatch(ctx context.Context, matchID uuid.UUID) ([]rule.MatchEvidence, error)
}

// AlertListFilter narrows an alert listing.
type AlertListFilter struct {
	TargetID   uuid.UUID
	Status     rule.AlertStatus
	Pagination pagination.Params
}

// AlertRepository persists and queries Alert rows.
type AlertRepository interface {
	// Upsert inserts a, or — if an alert for the same DetectionMatchID
	// already exists — widens LastObservedAt, exactly like
	// MatchRepository.Upsert, and never overwrites an existing Status.
	UpsertAlert(ctx context.Context, a rule.Alert) (result rule.Alert, created bool, err error)
	GetAlertByID(ctx context.Context, id uuid.UUID) (rule.Alert, error)
	ListAlerts(ctx context.Context, filter AlertListFilter) (pagination.Page[rule.Alert], error)
	UpdateAlertStatus(ctx context.Context, id uuid.UUID, status rule.AlertStatus) (rule.Alert, error)
	// SetInvestigation records the Phase 9 investigation an alert was
	// promoted into (phase11.md §22).
	SetInvestigation(ctx context.Context, id uuid.UUID, investigationID uuid.UUID) (rule.Alert, error)
}

// SuppressionListFilter narrows a suppression listing.
type SuppressionListFilter struct {
	TargetID   uuid.UUID
	Scope      rule.SuppressionScope
	ScopeID    uuid.UUID
	ActiveOnly bool
	Pagination pagination.Params
}

// SuppressionRepository persists and queries Suppression rows. A
// Suppression row is never deleted — see Remove (phase11.md §37).
type SuppressionRepository interface {
	CreateSuppression(ctx context.Context, s rule.Suppression) (rule.Suppression, error)
	ListSuppressions(ctx context.Context, filter SuppressionListFilter) (pagination.Page[rule.Suppression], error)
	// ActiveFor returns every non-removed, non-expired suppression
	// covering (scope, scopeID) as of now.
	ActiveFor(ctx context.Context, scope rule.SuppressionScope, scopeID uuid.UUID, now time.Time) ([]rule.Suppression, error)
	// Remove sets RemovedAt/RemovedBy — the row itself is preserved
	// (phase11.md §37's suppression-audit requirement).
	RemoveSuppression(ctx context.Context, id uuid.UUID, removedBy string) (rule.Suppression, error)
}
