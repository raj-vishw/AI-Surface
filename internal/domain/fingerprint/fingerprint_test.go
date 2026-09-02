package fingerprint

import (
	"testing"

	"github.com/google/uuid"
)

func validFingerprint() Fingerprint {
	return Fingerprint{
		AssetID:    uuid.New(),
		TargetID:   uuid.New(),
		Category:   CategoryWebServer,
		Technology: "nginx",
		Confidence: 0.9,
		Status:     StatusActive,
	}
}

func TestFingerprint_Validate_Valid(t *testing.T) {
	if err := validFingerprint().Validate(); err != nil {
		t.Errorf("expected a valid fingerprint, got: %v", err)
	}
}

func TestFingerprint_Validate_MissingAssetID(t *testing.T) {
	f := validFingerprint()
	f.AssetID = uuid.Nil
	if err := f.Validate(); err == nil {
		t.Error("expected an error for missing asset_id")
	}
}

func TestFingerprint_Validate_InvalidCategory(t *testing.T) {
	f := validFingerprint()
	f.Category = "not_a_category"
	if err := f.Validate(); err == nil {
		t.Error("expected an error for an invalid category")
	}
}

func TestFingerprint_Validate_EmptyTechnology(t *testing.T) {
	f := validFingerprint()
	f.Technology = "  "
	if err := f.Validate(); err == nil {
		t.Error("expected an error for empty technology")
	}
}

func TestFingerprint_Validate_InvalidConfidence(t *testing.T) {
	f := validFingerprint()
	f.Confidence = 1.5
	if err := f.Validate(); err == nil {
		t.Error("expected an error for out-of-range confidence")
	}
}

func TestScore_Level(t *testing.T) {
	tests := []struct {
		score Score
		want  Level
	}{
		{0.0, LevelWeak}, {0.29, LevelWeak},
		{0.30, LevelLow}, {0.59, LevelLow},
		{0.60, LevelMedium}, {0.79, LevelMedium},
		{0.80, LevelHigh}, {0.94, LevelHigh},
		{0.95, LevelVeryHigh}, {1.0, LevelVeryHigh},
	}
	for _, tc := range tests {
		if got := tc.score.Level(); got != tc.want {
			t.Errorf("Score(%v).Level() = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestIdentityKey_Deterministic(t *testing.T) {
	assetID := uuid.New()
	a := IdentityKey(assetID, CategoryWebServer, "nginx")
	b := IdentityKey(assetID, CategoryWebServer, "NGINX")
	if a != b {
		t.Errorf("IdentityKey should be case-insensitive on technology: %q vs %q", a, b)
	}

	other := IdentityKey(assetID, CategoryWebServer, "Apache")
	if a == other {
		t.Errorf("IdentityKey collided for distinct technologies")
	}
}
