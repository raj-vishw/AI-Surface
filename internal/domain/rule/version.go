package rule

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// DefaultEventSchemaVersion is the current normalized-event shape
// version (phase11.md §104/§105) — see internal/ruleengine's package doc
// comment for what "normalized event" means on this platform. A Version
// declares the schema version it was authored against so an incompatible
// future schema change can be detected rather than silently misevaluated
// (phase11.md §106: no silent rewriting).
const DefaultEventSchemaVersion = 1

// Version is one immutable, versioned rule definition (phase11.md §4/
// §5). It has no Update path anywhere in this codebase — immutable in
// history by construction, the same discipline
// internal/domain/investigation.Note uses: a change to a rule's logic is
// always a new Version, never a mutation of an existing one, so a
// historical DetectionMatch's (RuleID, RuleVersion) pair always remains
// reproducible.
type Version struct {
	ID      uuid.UUID
	RuleID  uuid.UUID
	Version int

	// Definition is the canonical JSON encoding of the engine-native rule
	// definition (internal/ruleengine.Definition) — validated and
	// compiled before being accepted (see internal/ruleengine.Validator/
	// Compile), never executed as arbitrary code (phase11.md §6/§8).
	Definition string
	// DefinitionHash is a content hash of Definition's *normalized* form
	// — excludes timestamps/database IDs/mutable metadata, so two
	// semantically-equivalent definitions hash identically (phase11.md
	// §72/§73). See internal/ruleengine.NormalizedHash.
	DefinitionHash string

	// Enabled is this version's own enable flag — a Rule's effective
	// enablement is Rule.Status == StatusEnabled AND its current
	// version's Enabled == true, so an analyst can enable a rule but
	// keep a specific version dormant (e.g. while a new version is being
	// validated).
	Enabled bool

	EventSchemaVersion int

	CreatedBy         string
	CreatedAt         time.Time
	ChangeDescription string
}

// Validate checks that v is internally consistent.
func (v Version) Validate() error {
	var errs validation.Errors

	if v.RuleID == uuid.Nil {
		errs = errs.Add("rule_id", "must not be empty")
	}
	if v.Version < 1 {
		errs = errs.Add("version", "must be at least 1")
	}
	if strings.TrimSpace(v.Definition) == "" {
		errs = errs.Add("definition", "must not be empty")
	}
	if strings.TrimSpace(v.DefinitionHash) == "" {
		errs = errs.Add("definition_hash", "must not be empty")
	}
	if v.EventSchemaVersion < 1 {
		errs = errs.Add("event_schema_version", "must be at least 1")
	}
	if strings.TrimSpace(v.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}

	return errs.ErrOrNil()
}
