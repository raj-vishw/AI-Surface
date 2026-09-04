package detection

import "github.com/google/uuid"

// Reference is a stable, external pointer supporting a Finding — never
// invented (phase8.md §49): only identifiers/URLs a detector actually
// knows to be correct (an RFC number, an OWASP category slug, an MDN
// page) are ever populated.
type Reference struct {
	Label string // e.g. "OWASP", "MDN", "RFC 6797"
	URL   string
}

// Finding is one detector's output for a single asset or endpoint —
// the in-memory counterpart of internal/domain/finding.Finding, produced
// entirely from Input with no database access of its own. Title/
// Description/Remediation must describe only what was observed, never
// claim exploitability (phase8.md §88): "CSP was not observed", not "the
// application is exploitable".
type Finding struct {
	AssetID uuid.UUID
	// EndpointID is set if and only if Scope is ScopeEndpoint.
	EndpointID *uuid.UUID

	DetectorID      string
	DetectorVersion int
	Title           string
	Description     string

	Category Category
	Scope    Scope
	Severity Severity
	// Confidence is capped defensively by Engine.Evaluate — a detector may
	// still return an out-of-range value by mistake and must not corrupt
	// the run.
	Confidence Confidence

	Evidence    []Evidence
	Remediation string
	References  []Reference

	// Metadata carries any additional structured detail worth persisting
	// alongside the finding (e.g. the specific header name checked) —
	// sanitized by internal/service/detection before storage, exactly
	// like every other Metadata map in this project.
	Metadata map[string]any
}

// IdentityKey returns f's engine-side deterministic grouping key — the
// same (asset, endpoint?, detector) shape internal/domain/finding.
// IdentityKey uses, computed independently here to keep this package free
// of a domain dependency (see fingerprint.go).
func (f Finding) IdentityKey() string {
	return IdentityKey(f.AssetID, f.EndpointID, f.DetectorID)
}
