package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// EvidenceType classifies what kind of observation an Evidence record
// captures.
type EvidenceType string

// Recognized evidence types.
const (
	EvidenceDNSRecord           EvidenceType = "DNS_RECORD"
	EvidenceHTTPResponse        EvidenceType = "HTTP_RESPONSE"
	EvidenceTLSCertificate      EvidenceType = "TLS_CERTIFICATE"
	EvidencePortObservation     EvidenceType = "PORT_OBSERVATION"
	EvidenceHeader              EvidenceType = "HEADER"
	EvidenceHTML                EvidenceType = "HTML"
	EvidenceRepositoryReference EvidenceType = "REPOSITORY_REFERENCE"
	EvidenceCloudReference      EvidenceType = "CLOUD_REFERENCE"
	EvidenceManual              EvidenceType = "MANUAL"
)

var validEvidenceTypes = map[EvidenceType]bool{
	EvidenceDNSRecord: true, EvidenceHTTPResponse: true, EvidenceTLSCertificate: true,
	EvidencePortObservation: true, EvidenceHeader: true, EvidenceHTML: true,
	EvidenceRepositoryReference: true, EvidenceCloudReference: true, EvidenceManual: true,
}

// Valid reports whether t is a recognized evidence type.
func (t EvidenceType) Valid() bool { return validEvidenceTypes[t] }

// Evidence is a single, immutable observation that justifies believing an
// Asset exists or has some property. Evidence is append-only: a changed
// observation is recorded as a new Evidence row, never as a mutation of an
// existing one — see docs/architecture/asset-model.md for the rationale.
type Evidence struct {
	ID           uuid.UUID
	AssetID      uuid.UUID
	Source       string
	EvidenceType EvidenceType
	EvidenceData map[string]any
	Fingerprint  string
	Confidence   Confidence
	ObservedAt   time.Time
	CreatedAt    time.Time
}

// Validate checks that e is internally consistent: non-empty AssetID and
// Source, a recognized EvidenceType, and a valid Confidence.
func (e Evidence) Validate() error {
	var errs validation.Errors

	if e.AssetID == uuid.Nil {
		errs = errs.Add("asset_id", "must not be empty")
	}
	if strings.TrimSpace(e.Source) == "" {
		errs = errs.Add("source", "must not be empty")
	}
	if !e.EvidenceType.Valid() {
		errs = errs.Add("evidence_type", "must be a recognized evidence type")
	}
	if err := e.Confidence.Validate(); err != nil {
		errs = errs.Add("confidence", "must be between 0.0 and 1.0")
	}

	return errs.ErrOrNil()
}

// EvidenceFingerprint returns the SHA-256 hex digest of data's canonical
// JSON encoding. encoding/json marshals Go maps with keys in sorted order,
// which makes this deterministic regardless of the map's iteration order or
// how the caller built it. Compute the fingerprint AFTER sanitizing data
// with SanitizeMetadata — the fingerprint, like the stored evidence_data
// itself, must never be derived from (or leak, via a rainbow-table-style
// lookup) an unredacted secret.
//
// Together with (asset_id, source, evidence_type), this fingerprint forms
// the deduplication key that prevents identical evidence from being stored
// once per scan indefinitely (see internal/repository/asset).
func EvidenceFingerprint(data map[string]any) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("encoding evidence data: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
