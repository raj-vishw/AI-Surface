package reporting

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// EvidenceItemType names what kind of already-persisted entity one
// EvidenceItem references (phase14.md §37/§45) — deliberately mirrors
// internal/domain/investigation.EntityType's vocabulary rather than
// importing it (this package's own independence discipline — see the
// package doc comment).
type EvidenceItemType string

// Recognized evidence item types.
const (
	EvidenceFinding       EvidenceItemType = "finding"
	EvidenceAlert         EvidenceItemType = "alert"
	EvidenceDetection     EvidenceItemType = "detection_match"
	EvidenceCorrelation   EvidenceItemType = "correlation"
	EvidenceInvestigation EvidenceItemType = "investigation"
	EvidenceIntelligence  EvidenceItemType = "intelligence_record"
	EvidenceAsset         EvidenceItemType = "asset"
	EvidenceEvent         EvidenceItemType = "event"
)

var validEvidenceItemTypes = map[EvidenceItemType]bool{
	EvidenceFinding: true, EvidenceAlert: true, EvidenceDetection: true,
	EvidenceCorrelation: true, EvidenceInvestigation: true, EvidenceIntelligence: true,
	EvidenceAsset: true, EvidenceEvent: true,
}

// Valid reports whether t is a recognized evidence item type.
func (t EvidenceItemType) Valid() bool { return validEvidenceItemTypes[t] }

// Package is an evidence export for authorized analysts (phase14.md
// §45) — always scoped to one report and never a dump of an entire
// target's data (phase14.md §45: "do not automatically export all
// project data").
type Package struct {
	ID       uuid.UUID
	TargetID uuid.UUID
	ReportID *uuid.UUID

	CreatedBy string
	CreatedAt time.Time
}

// Validate checks that p is internally consistent.
func (p Package) Validate() error {
	var errs validation.Errors
	if p.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(p.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}
	return errs.ErrOrNil()
}

// Item is one manifest entry within a Package (phase14.md §46) — a
// reference plus an integrity hash, never a copy of the referenced
// row's own content.
type Item struct {
	ID        uuid.UUID
	PackageID uuid.UUID

	ItemType    EvidenceItemType
	ReferenceID uuid.UUID

	// Hash is a SHA-256 hash of the item's canonical (already-redacted)
	// string representation at export time (phase14.md §47) — used only
	// for integrity checking, never as an authentication mechanism
	// (phase14.md §47's own explicit instruction).
	Hash string

	// Timestamp is the referenced item's own observation time (its
	// FirstSeen/CreatedAt/...) — never the export time, which is
	// Package.CreatedAt instead.
	Timestamp time.Time

	CreatedAt time.Time
}

// Validate checks that i is internally consistent.
func (i Item) Validate() error {
	var errs validation.Errors
	if i.PackageID == uuid.Nil {
		errs = errs.Add("package_id", "must not be empty")
	}
	if !i.ItemType.Valid() {
		errs = errs.Add("item_type", "must be a recognized evidence item type")
	}
	if i.ReferenceID == uuid.Nil {
		errs = errs.Add("reference_id", "must not be empty")
	}
	if strings.TrimSpace(i.Hash) == "" {
		errs = errs.Add("hash", "must not be empty")
	}
	return errs.ErrOrNil()
}
