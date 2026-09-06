package correlation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// StageType names one generic stage a correlated activity sequence may
// pass through (phase12.md §41) — deliberately generic (not MITRE
// ATT&CK-mapped) and never fabricated: a chain simply omits a stage it
// has no evidence for (phase12.md §44 — see Gap on AttackChain).
type StageType string

// Recognized attack-chain stages.
const (
	StageInitialActivity   StageType = "initial_activity"
	StageAuthentication    StageType = "authentication"
	StageExecution         StageType = "execution"
	StagePrivilegeChange   StageType = "privilege_change"
	StagePersistenceSignal StageType = "persistence_signal"
	StageDiscoverySignal   StageType = "discovery_signal"
	StageNetworkActivity   StageType = "network_activity"
	StageDataAccess        StageType = "data_access"
	StageImpactSignal      StageType = "impact_signal"
)

var validStages = map[StageType]bool{
	StageInitialActivity: true, StageAuthentication: true, StageExecution: true,
	StagePrivilegeChange: true, StagePersistenceSignal: true, StageDiscoverySignal: true,
	StageNetworkActivity: true, StageDataAccess: true, StageImpactSignal: true,
}

// Valid reports whether t is a recognized stage type.
func (t StageType) Valid() bool { return validStages[t] }

// StageEvidenceRef is one (node type, reference id) pair a stage cites as
// its evidence (phase12.md §42) — stored as a small JSON array on the
// stage row rather than a seventh table, the same "opaque JSON for a
// small, append-only, never-independently-queried structure" choice
// internal/domain/rule.Version.Definition makes for its own Definition.
type StageEvidenceRef struct {
	NodeType    NodeType
	ReferenceID uuid.UUID
}

// AttackChainStage is one stage of an AttackChain (phase12.md §41/§42).
type AttackChainStage struct {
	ID            uuid.UUID
	AttackChainID uuid.UUID

	Stage StageType
	// Order is this stage's position in the chain's chronological
	// sequence (phase12.md §38's deterministic ordering, applied to
	// stages) — never database insertion order.
	Order int
	// Confidence is this specific stage's own confidence (phase12.md
	// §43) — a chain's overall Confidence is derived from every stage's
	// confidence, never a bare average (see internal/correlation's
	// chain-confidence formula).
	Confidence EdgeConfidence

	Evidence []StageEvidenceRef

	CreatedAt time.Time
}

// Validate checks that s is internally consistent.
func (s AttackChainStage) Validate() error {
	var errs validation.Errors

	if s.AttackChainID == uuid.Nil {
		errs = errs.Add("attack_chain_id", "must not be empty")
	}
	if !s.Stage.Valid() {
		errs = errs.Add("stage", "must be a recognized stage type")
	}
	if !s.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if len(s.Evidence) == 0 {
		errs = errs.Add("evidence", "must reference at least one node — a stage is never asserted without evidence")
	}

	return errs.ErrOrNil()
}

// AttackChain is a narrative representation of one Correlation's graph as
// an ordered sequence of stages (phase12.md §40). It is explicitly NOT
// automatic proof of an attack — Status uses the same suspected/
// confirmed/dismissed workflow as its parent Correlation, and a chain
// with gaps (phase12.md §44) represents exactly that: an observed gap, not
// an invented stage.
type AttackChain struct {
	ID            uuid.UUID
	CorrelationID uuid.UUID

	Name        string
	Description string

	Confidence Confidence
	Severity   Severity
	Status     Status

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that c is internally consistent.
func (c AttackChain) Validate() error {
	var errs validation.Errors

	if c.CorrelationID == uuid.Nil {
		errs = errs.Add("correlation_id", "must not be empty")
	}
	if strings.TrimSpace(c.Name) == "" {
		errs = errs.Add("name", "must not be empty")
	}
	if !c.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if !c.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !c.Status.Valid() {
		errs = errs.Add("status", "must be a recognized correlation status")
	}

	return errs.ErrOrNil()
}
