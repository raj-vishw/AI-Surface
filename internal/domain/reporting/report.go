// Package reporting defines Phase 14's report/evidence-package/control-
// evidence persistence model — mirroring internal/domain/correlation and
// internal/domain/ai's shape and independence discipline: no dependency
// on any other domain package; every cross-entity reference is a bare
// uuid.UUID plus a string type tag, never an imported type.
//
// Report versioning mirrors internal/domain/rule.Version exactly
// (phase14.md §77: "regenerating a report should create a new report
// version... do not overwrite the original"): a Report row is immutable
// once created — there is no UpdateReport operation anywhere in this
// codebase except Approve, which only ever sets ApprovedBy/ApprovedAt/
// ApprovalNotes, never Content (the same one deliberate, narrow
// exception internal/domain/investigation.Note's AIGenerated/ApprovedBy
// fields already establish for Phase 13's own AI-generated notes).
package reporting

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Type names what kind of report this is (phase14.md §32).
type Type string

// Recognized report types.
const (
	TypeInvestigation Type = "investigation"
	TypeAsset         Type = "asset"
	TypeAttackSurface Type = "attack_surface"
	TypeDetection     Type = "detection"
	TypeCorrelation   Type = "correlation"
	TypeExecutive     Type = "executive"
	TypeAudit         Type = "audit"
	TypeCompliance    Type = "compliance"
)

var validTypes = map[Type]bool{
	TypeInvestigation: true, TypeAsset: true, TypeAttackSurface: true,
	TypeDetection: true, TypeCorrelation: true, TypeExecutive: true,
	TypeAudit: true, TypeCompliance: true,
}

// Valid reports whether t is a recognized report type.
func (t Type) Valid() bool { return validTypes[t] }

// RequiresSubject reports whether t is scoped to one specific entity
// (an investigation, asset, or correlation id) rather than the whole
// target (phase14.md §33-36's per-type section lists: investigation/
// asset/detection/correlation reports name one subject; attack-surface/
// executive/audit/compliance reports summarize the whole target).
func (t Type) RequiresSubject() bool {
	switch t {
	case TypeInvestigation, TypeAsset, TypeCorrelation:
		return true
	default:
		return false
	}
}

// Status tracks a Report's review lifecycle (phase14.md §39).
type Status string

// Recognized statuses.
const (
	StatusDraft     Status = "draft"
	StatusGenerated Status = "generated"
	StatusReviewed  Status = "reviewed"
	StatusApproved  Status = "approved"
)

var validStatuses = map[Status]bool{
	StatusDraft: true, StatusGenerated: true, StatusReviewed: true, StatusApproved: true,
}

// Valid reports whether s is a recognized status.
func (s Status) Valid() bool { return validStatuses[s] }

// Report is one generated, versioned report (phase14.md §31/§38).
// Content holds the rendered Sections (see sections.go, in
// internal/reporting) as a JSON document — an opaque blob to this
// package, the same "small, structured JSON, not a further exploded
// table" choice internal/domain/rule.Version.Definition and
// internal/domain/correlation.AttackChainStage.Evidence already make.
type Report struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	ReportType Type
	// SubjectID is the investigation/asset/correlation id this report is
	// about — nil for target-wide reports (attack-surface, executive,
	// audit, compliance). See Type.RequiresSubject.
	SubjectID *uuid.UUID

	// Version is this (ReportType, SubjectID) pair's sequential version
	// number, starting at 1 — mirrors rule.Version.Version exactly.
	// Regenerating never overwrites an earlier version's row.
	Version int

	Title   string
	Content string // canonical JSON — see internal/reporting.Sections

	Status Status

	// ContentHash is a SHA-256 hash of Content — phase14.md §41's
	// integrity-verification hash, computed once at generation and never
	// recomputed afterward (a later mismatch would mean the row was
	// modified outside this platform's own write path).
	ContentHash string

	GeneratedBy string
	GeneratedAt time.Time

	// Provider/Model/PromptVersion are set only when this report's
	// content includes an AI-generated section (phase14.md §38) — nil
	// for a fully deterministic report.
	Provider      *string
	Model         *string
	PromptVersion *string

	ApprovedBy    *string
	ApprovedAt    *time.Time
	ApprovalNotes string

	CreatedAt time.Time
}

// Validate checks that r is internally consistent.
func (r Report) Validate() error {
	var errs validation.Errors

	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !r.ReportType.Valid() {
		errs = errs.Add("report_type", "must be a recognized report type")
	}
	if r.ReportType.RequiresSubject() && (r.SubjectID == nil || *r.SubjectID == uuid.Nil) {
		errs = errs.Add("subject_id", "must be set for this report type")
	}
	if r.Version < 1 {
		errs = errs.Add("version", "must be at least 1")
	}
	if strings.TrimSpace(r.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if strings.TrimSpace(r.Content) == "" {
		errs = errs.Add("content", "must not be empty")
	}
	if !r.Status.Valid() {
		errs = errs.Add("status", "must be a recognized status")
	}
	if strings.TrimSpace(r.ContentHash) == "" {
		errs = errs.Add("content_hash", "must not be empty")
	}
	if strings.TrimSpace(r.GeneratedBy) == "" {
		errs = errs.Add("generated_by", "must not be empty")
	}
	if r.Status == StatusApproved && (r.ApprovedBy == nil || strings.TrimSpace(*r.ApprovedBy) == "") {
		errs = errs.Add("approved_by", "must be set when status is approved")
	}

	return errs.ErrOrNil()
}
