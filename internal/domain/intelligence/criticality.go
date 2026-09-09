package intelligence

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Criticality is analyst/business context about how important an asset
// is (phase10.md §36) — never inferred from a domain name or any other
// observed signal (phase10.md §36); it is set only through an explicit
// analyst action.
type Criticality string

// Recognized criticality levels.
const (
	CriticalityLow      Criticality = "low"
	CriticalityNormal   Criticality = "normal"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

var validCriticalities = map[Criticality]bool{
	CriticalityLow: true, CriticalityNormal: true, CriticalityHigh: true, CriticalityCritical: true,
}

// Valid reports whether c is a recognized criticality level.
func (c Criticality) Valid() bool { return validCriticalities[c] }

// Points returns c's contribution to the risk model's asset_criticality
// factor (phase10.md §34/§37) — documented weights, not arbitrary
// (phase10.md §37).
func (c Criticality) Points() int {
	switch c {
	case CriticalityCritical:
		return 15
	case CriticalityHigh:
		return 10
	case CriticalityNormal:
		return 0
	case CriticalityLow:
		return -5
	default:
		return 0
	}
}

// AssetCriticality records the current analyst-assigned criticality for
// one asset. It is a mutable "current state" row — like
// fingerprint.Fingerprint or finding.Finding, history of prior values is
// not separately preserved (phase10.md doesn't require it; only
// intelligence verdicts/risk scores must preserve history — §45/§47).
type AssetCriticality struct {
	AssetID     uuid.UUID
	TargetID    uuid.UUID
	Criticality Criticality
	SetBy       string
	SetAt       time.Time
	UpdatedAt   time.Time
}

// Validate checks that a is internally consistent.
func (a AssetCriticality) Validate() error {
	var errs validation.Errors

	if a.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if a.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !a.Criticality.Valid() {
		errs = errs.Add("criticality", "must be a recognized criticality level")
	}
	if strings.TrimSpace(a.SetBy) == "" {
		errs = errs.Add("set_by", "must not be empty")
	}

	return errs.ErrOrNil()
}
