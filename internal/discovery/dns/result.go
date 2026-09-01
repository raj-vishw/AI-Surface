package dns

import (
	"time"

	"github.com/google/uuid"
)

// RecordResult is one DNS record query's outcome for a single (name,
// type) pair.
type RecordResult struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID

	Name string
	Type RecordType

	State   ResolutionState
	Records []Record // populated only when State == StateResolved

	WildcardAffected bool // this name's result matches the domain's wildcard baseline — see wildcard.go

	Duration   time.Duration
	ObservedAt time.Time

	// Error carries a transport-level failure description for
	// StateTimeout/StateError — never a raw resolver/protocol detail
	// beyond what's needed to explain the failure (phase5.md §31: "do not
	// expose internal resolver errors directly").
	Error string
}

// SubdomainResult is one subdomain candidate's resolution outcome —
// distinct from RecordResult because a subdomain candidate rolls up
// potentially several record types into one "is this a real subdomain"
// verdict (phase5.md §26).
type SubdomainResult struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID

	Name       string
	Source     CandidateSource
	State      ResolutionState
	Records    []Record
	Confidence float64

	WildcardAffected bool

	HTTPCandidate bool // phase5.md §46: metadata only, never triggers an HTTP scan itself

	ObservedAt time.Time
}

// Succeeded reports whether s represents a genuinely discovered subdomain
// worth normalizing into an asset — resolved, with real evidence, and not
// indistinguishable wildcard noise.
func (s SubdomainResult) Succeeded() bool {
	return s.State == StateResolved && !s.WildcardAffected
}

// Summary aggregates one DNS discovery run's record and subdomain results
// (phase5.md §31/§56).
type Summary struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID
	Target   string

	NamesQueried int
	Resolved     int
	NXDOMAIN     int
	NoAnswer     int
	Timeouts     int
	Errors       int

	RecordCounts map[RecordType]int

	SubdomainsDiscovered int
	WildcardDetected     bool

	Duration time.Duration

	RecordResults    []RecordResult
	SubdomainResults []SubdomainResult
	Wildcard         *WildcardDetection
}
