package finding

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvidence_Validate(t *testing.T) {
	e := Evidence{
		FindingID: uuid.New(), Source: "detection", EvidenceType: EvidenceHTTPHeader, Confidence: 0.8,
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	bad := e
	bad.FindingID = uuid.Nil
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for missing finding_id")
	}

	bad = e
	bad.EvidenceType = "not_a_type"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for invalid evidence_type")
	}
}

func TestEvidenceFingerprint_Deterministic(t *testing.T) {
	data := map[string]any{"header": "Content-Security-Policy", "observed": false}
	f1, err := EvidenceFingerprint(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f2, err := EvidenceFingerprint(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f1 != f2 {
		t.Fatal("expected identical data to fingerprint identically")
	}

	other, err := EvidenceFingerprint(map[string]any{"header": "X-Frame-Options", "observed": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f1 == other {
		t.Fatal("expected different data to fingerprint differently")
	}
}
