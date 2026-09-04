package finding

import (
	"testing"

	"github.com/google/uuid"
)

func validFinding() Finding {
	return Finding{
		TargetID: uuid.New(), AssetID: uuid.New(),
		DetectorID: "security_headers.missing-hsts", Title: "Missing HSTS",
		Category: CategorySecurityHeaders, Scope: ScopeAsset,
		Severity: SeverityLow, DetectorSeverity: SeverityLow, Confidence: 0.9,
		Status: StatusOpen, IdentityKey: "x",
	}
}

func TestValidate_ValidFinding(t *testing.T) {
	f := validFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidate_MissingTargetID(t *testing.T) {
	f := validFinding()
	f.TargetID = uuid.Nil
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for missing target_id")
	}
}

func TestValidate_EndpointScopeRequiresEndpointID(t *testing.T) {
	f := validFinding()
	f.Scope = ScopeEndpoint
	if err := f.Validate(); err == nil {
		t.Fatal("expected error: endpoint scope without endpoint_id")
	}
	id := uuid.New()
	f.EndpointID = &id
	if err := f.Validate(); err != nil {
		t.Fatalf("expected valid once endpoint_id set, got %v", err)
	}
}

func TestValidate_AssetScopeRejectsEndpointID(t *testing.T) {
	f := validFinding()
	id := uuid.New()
	f.EndpointID = &id
	if err := f.Validate(); err == nil {
		t.Fatal("expected error: asset scope with endpoint_id set")
	}
}

func TestValidate_InvalidCategory(t *testing.T) {
	f := validFinding()
	f.Category = "not_a_category"
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for invalid category")
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	f := validFinding()
	f.Severity = "extreme"
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestValidate_ConfidenceOutOfRange(t *testing.T) {
	f := validFinding()
	f.Confidence = 1.5
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for out-of-range confidence")
	}
}

func TestValidate_SuppressedStatusRequiresReason(t *testing.T) {
	f := validFinding()
	f.Status = StatusFalsePositive
	if err := f.Validate(); err == nil {
		t.Fatal("expected error: false_positive without suppression_reason")
	}
	f.SuppressionReason = "confirmed not applicable — internal test harness only"
	if err := f.Validate(); err != nil {
		t.Fatalf("expected valid once reason set, got %v", err)
	}
}

func TestValidate_MissingIdentityKey(t *testing.T) {
	f := validFinding()
	f.IdentityKey = ""
	if err := f.Validate(); err == nil {
		t.Fatal("expected error for missing identity_key")
	}
}

func TestSeverity_Rank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical must outrank high")
	}
	if SeverityInformational.Rank() != 0 {
		t.Fatalf("expected informational rank 0, got %d", SeverityInformational.Rank())
	}
	if Severity("bogus").Rank() != -1 {
		t.Fatal("expected unrecognized severity to rank -1")
	}
}

func TestConfidence_Level(t *testing.T) {
	cases := []struct {
		c    Confidence
		want Level
	}{
		{0.0, LevelVeryLow}, {0.30, LevelLow}, {0.50, LevelMedium},
		{0.75, LevelHigh}, {0.95, LevelVeryHigh}, {1.0, LevelVeryHigh},
	}
	for _, tc := range cases {
		if got := tc.c.Level(); got != tc.want {
			t.Errorf("Confidence(%.2f).Level() = %s, want %s", tc.c, got, tc.want)
		}
	}
}

func TestIdentityKey_DeterministicAndScoped(t *testing.T) {
	targetID, assetID := uuid.New(), uuid.New()
	k1 := IdentityKey(targetID, assetID, nil, "security_headers.missing-hsts")
	k2 := IdentityKey(targetID, assetID, nil, "security_headers.missing-hsts")
	if k1 != k2 {
		t.Fatal("expected identical inputs to produce identical identity keys")
	}

	endpointID := uuid.New()
	k3 := IdentityKey(targetID, assetID, &endpointID, "security_headers.missing-hsts")
	if k3 == k1 {
		t.Fatal("expected endpoint-scoped identity to differ from asset-scoped identity")
	}
}

func TestStatus_Open(t *testing.T) {
	if !StatusOpen.Open() || !StatusReopened.Open() {
		t.Fatal("expected open/reopened to be Open")
	}
	if StatusResolved.Open() || StatusAcceptedRisk.Open() || StatusFalsePositive.Open() {
		t.Fatal("expected resolved/accepted_risk/false_positive to not be Open")
	}
}
