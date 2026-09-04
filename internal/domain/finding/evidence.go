package finding

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

// EvidenceType classifies what kind of observation a finding Evidence
// record captures (phase8.md §9).
type EvidenceType string

// Recognized evidence types.
const (
	EvidenceHTTPHeader      EvidenceType = "http_header"
	EvidenceHTTPStatus      EvidenceType = "http_status"
	EvidenceResponseMeta    EvidenceType = "response_metadata"
	EvidenceTLSMetadata     EvidenceType = "tls_metadata"
	EvidenceCookieMetadata  EvidenceType = "cookie_metadata"
	EvidenceEndpointMeta    EvidenceType = "endpoint_metadata"
	EvidenceTechnology      EvidenceType = "technology_fingerprint"
	EvidenceDNSObservation  EvidenceType = "dns_observation"
	EvidenceServiceMeta     EvidenceType = "service_observation"
	EvidenceOpenAPIMeta     EvidenceType = "openapi_metadata"
	EvidenceClassification  EvidenceType = "endpoint_classification"
	EvidenceConfiguration   EvidenceType = "configuration_observation"
	EvidenceResponseExcerpt EvidenceType = "response_excerpt"
)

var validEvidenceTypes = map[EvidenceType]bool{
	EvidenceHTTPHeader: true, EvidenceHTTPStatus: true, EvidenceResponseMeta: true,
	EvidenceTLSMetadata: true, EvidenceCookieMetadata: true, EvidenceEndpointMeta: true,
	EvidenceTechnology: true, EvidenceDNSObservation: true, EvidenceServiceMeta: true,
	EvidenceOpenAPIMeta: true, EvidenceClassification: true, EvidenceConfiguration: true,
	EvidenceResponseExcerpt: true,
}

// Valid reports whether t is a recognized finding evidence type.
func (t EvidenceType) Valid() bool { return validEvidenceTypes[t] }

// Evidence is one immutable observation that justifies a Finding
// (phase8.md §8: "Evidence must explain why the finding exists"), mirroring
// asset.Evidence/domainendpoint.Evidence/fingerprint.Evidence's
// append-only role. Multiple Evidence rows commonly back one Finding —
// e.g. the same missing-CSP condition corroborated by both an HTML scan
// and a later re-crawl (phase8.md §44).
type Evidence struct {
	ID           uuid.UUID
	FindingID    uuid.UUID
	Source       string // "detection", "http", "endpoint", "fingerprint", "network", "dns"
	EvidenceType EvidenceType
	EvidenceData map[string]any
	Fingerprint  string
	Confidence   Confidence
	ObservedAt   time.Time
	CreatedAt    time.Time
}

// Validate checks that e is internally consistent.
func (e Evidence) Validate() error {
	var errs validation.Errors

	if e.FindingID == uuid.Nil {
		errs = errs.Add("finding_id", "must not be empty")
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
// JSON encoding — the same deduplication mechanism
// asset.EvidenceFingerprint/domainendpoint.EvidenceFingerprint provide,
// kept as an independent copy here for the same one-directional-dependency
// reason those packages give.
func EvidenceFingerprint(data map[string]any) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("encoding evidence data: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
