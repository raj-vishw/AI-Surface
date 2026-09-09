package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Evidence is one immutable observation that justifies believing an
// Endpoint exists or has some property — mirroring asset.Evidence's role
// for Asset (this package deliberately keeps its own copy rather than
// importing internal/domain/asset, preserving the one-directional
// dependency graph asset -> endpoint documented on Status). Evidence is
// append-only: a changed observation is a new row, never a mutation of
// an existing one (phase7.md §42).
type Evidence struct {
	ID           uuid.UUID
	EndpointID   uuid.UUID
	AssetID      uuid.UUID
	ScanID       *uuid.UUID
	Source       string // "html_link", "html_form", "javascript", "sitemap", "robots", "openapi", "swagger", "redirect", "seed", "manual"
	EvidenceData map[string]any
	Fingerprint  string
	Confidence   float64
	ObservedAt   time.Time
	CreatedAt    time.Time
}

// Validate checks that e is internally consistent.
func (e Evidence) Validate() error {
	var errs validation.Errors

	if e.EndpointID == uuid.Nil {
		errs = errs.Add("endpoint_id", "must not be empty")
	}
	if e.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if e.Source == "" {
		errs = errs.Add("source", "must not be empty")
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}

	return errs.ErrOrNil()
}

// EvidenceFingerprint returns the SHA-256 hex digest of data's canonical
// JSON encoding — the same deduplication mechanism
// asset.EvidenceFingerprint provides, kept as an independent copy here
// for the same reason the rest of this file is (phase7.md §42's "every
// endpoint should have evidence... sanitized" mirrors phase2's discipline
// exactly, applied to a new entity).
func EvidenceFingerprint(data map[string]any) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("encoding evidence data: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
