package fingerprint

import (
	"testing"

	"github.com/google/uuid"
)

func TestEvidence_Validate_Valid(t *testing.T) {
	e := Evidence{
		FingerprintID: uuid.New(),
		AssetID:       uuid.New(),
		Confidence:    0.9,
		Signals:       []Signal{{Type: "http_header", Field: "Server", Value: "nginx", Weight: 0.9}},
	}
	if err := e.Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestEvidence_Validate_NoSignals(t *testing.T) {
	e := Evidence{FingerprintID: uuid.New(), AssetID: uuid.New(), Confidence: 0.9}
	if err := e.Validate(); err == nil {
		t.Error("expected an error for no signals")
	}
}

func TestSignalsFingerprint_Deterministic(t *testing.T) {
	signals := []Signal{{Type: "http_header", Field: "Server", Value: "nginx", Weight: 0.9}}
	a, err := SignalsFingerprint(signals)
	if err != nil {
		t.Fatalf("SignalsFingerprint: %v", err)
	}
	b, err := SignalsFingerprint(signals)
	if err != nil {
		t.Fatalf("SignalsFingerprint: %v", err)
	}
	if a != b {
		t.Errorf("SignalsFingerprint not deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("SignalsFingerprint length = %d, want 64 (SHA-256 hex)", len(a))
	}
}

func TestSignalsFingerprint_DistinctForDifferentSignals(t *testing.T) {
	a, _ := SignalsFingerprint([]Signal{{Type: "http_header", Field: "Server", Value: "nginx", Weight: 0.9}})
	b, _ := SignalsFingerprint([]Signal{{Type: "http_header", Field: "Server", Value: "apache", Weight: 0.9}})
	if a == b {
		t.Error("SignalsFingerprint collided for distinct signal sets")
	}
}
