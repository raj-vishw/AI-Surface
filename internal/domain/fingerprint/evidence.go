package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Signal is one concrete piece of matched evidence — e.g. "the Server
// header equals nginx/1.25.3, weight 0.90" — the atomic unit
// explainability is built from (phase6.md §5). It is used both as the
// engine's live match output (internal/fingerprint) and as the shape
// persisted in Evidence.Signals; the two packages share no Go type (see
// this package's doc comment), only this JSON-compatible shape.
type Signal struct {
	// Type is the signal's kind — "http_header", "html", "script",
	// "dns_cname", "port", ... (internal/fingerprint.SignalType's string
	// form; kept as a plain string here so this package never imports the
	// engine package).
	Type string `json:"type"`
	// Field names what within Type was inspected, e.g. "Server" for an
	// http_header signal, "CNAME" for a dns_record signal.
	Field string `json:"field"`
	// Value is the (already-redacted, safe) observed value that matched.
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
	// Description is a short, human-readable explanation — "Server header
	// matches nginx signature" — surfaced by --explain.
	Description string `json:"description,omitempty"`
}

// Evidence is one immutable, timestamped snapshot of the signals that
// justified a Fingerprint as of one analysis run — the append-only trail
// mirroring asset.Evidence's role for Fingerprint the way asset.Evidence
// backs Asset (phase6.md §20/§22). A Fingerprint's Metadata always holds
// only the *latest* such snapshot; every historical one lives here,
// never overwritten or deleted.
type Evidence struct {
	ID            uuid.UUID
	FingerprintID uuid.UUID
	AssetID       uuid.UUID
	ScanID        *uuid.UUID
	Source        string // fixed "fingerprint" — distinct from the discovery Source vocabulary (http/network/dns), since this evidence is derived, not directly observed
	Signals       []Signal
	Confidence    Score
	Fingerprint   string // SHA-256 hex of the canonical signal set — the dedup key (see SignalsFingerprint), analogous to asset.Evidence.Fingerprint
	ObservedAt    time.Time
	CreatedAt     time.Time
}

// Validate checks that e is internally consistent.
func (e Evidence) Validate() error {
	var errs validation.Errors

	if e.FingerprintID == uuid.Nil {
		errs = errs.Add("fingerprint_id", "must not be empty")
	}
	if e.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if err := e.Confidence.Validate(); err != nil {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}
	if len(e.Signals) == 0 {
		errs = errs.Add("signals", "must contain at least one signal")
	}

	return errs.ErrOrNil()
}

// SignalsFingerprint returns the SHA-256 hex digest of signals' canonical
// JSON encoding, deterministic regardless of slice/map iteration order in
// the caller (encoding/json marshals struct fields in declaration order
// and map keys sorted). Together with (fingerprint_id), this forms the
// deduplication key that prevents an unchanged signal set from producing
// a brand-new evidence row on every re-analysis (the same discipline
// Phase 3/4/5 apply to asset_evidence, and the same reason scan_id is
// deliberately excluded from the hashed shape — see internal/service/
// fingerprint).
func SignalsFingerprint(signals []Signal) (string, error) {
	encoded, err := json.Marshal(signals)
	if err != nil {
		return "", fmt.Errorf("encoding signals: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
