package asset

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvidenceFingerprint_Deterministic(t *testing.T) {
	data := map[string]any{"status_code": float64(200), "content_type": "application/json"}
	fp1, err := EvidenceFingerprint(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fp2, err := EvidenceFingerprint(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint is not deterministic: %q vs %q", fp1, fp2)
	}
}

func TestEvidenceFingerprint_OrderIndependent(t *testing.T) {
	a := map[string]any{"a": 1.0, "b": 2.0, "c": 3.0}
	// Rebuilt in a different insertion order — Go map iteration order is
	// randomized, but encoding/json always marshals map keys sorted, so the
	// fingerprint must match regardless of how the map was built.
	b := map[string]any{"c": 3.0, "a": 1.0, "b": 2.0}

	fpA, err := EvidenceFingerprint(a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fpB, err := EvidenceFingerprint(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fpA != fpB {
		t.Errorf("fingerprint depends on map insertion order: %q vs %q", fpA, fpB)
	}
}

func TestEvidenceFingerprint_DifferentDataDiffers(t *testing.T) {
	fp1, err := EvidenceFingerprint(map[string]any{"status_code": 200.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fp2, err := EvidenceFingerprint(map[string]any{"status_code": 404.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp1 == fp2 {
		t.Error("different evidence data must not share a fingerprint")
	}
}

func TestEvidenceFingerprint_IsSHA256Hex(t *testing.T) {
	fp, err := EvidenceFingerprint(map[string]any{"a": 1.0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
}

func TestEvidenceValidate(t *testing.T) {
	valid := Evidence{
		AssetID:      uuid.New(),
		Source:       "http",
		EvidenceType: EvidenceHTTPResponse,
		Confidence:   0.8,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid evidence, got: %v", err)
	}

	missingAsset := valid
	missingAsset.AssetID = uuid.Nil
	if err := missingAsset.Validate(); err == nil {
		t.Error("expected error for missing asset id")
	}

	badType := valid
	badType.EvidenceType = "NOT_A_TYPE"
	if err := badType.Validate(); err == nil {
		t.Error("expected error for unrecognized evidence type")
	}

	badConfidence := valid
	badConfidence.Confidence = 2.0
	if err := badConfidence.Validate(); err == nil {
		t.Error("expected error for out-of-range confidence")
	}
}
