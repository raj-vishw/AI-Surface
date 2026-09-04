package detection

import (
	"testing"

	"github.com/google/uuid"
)

func TestMergeFindings_CollapsesSameIdentity(t *testing.T) {
	assetID := uuid.New()
	findings := []Finding{
		{AssetID: assetID, DetectorID: "d", Severity: SeverityLow, Confidence: 0.5,
			Evidence: []Evidence{{Type: EvidenceHTTPHeader}}},
		{AssetID: assetID, DetectorID: "d", Severity: SeverityHigh, Confidence: 0.8,
			Evidence: []Evidence{{Type: EvidenceResponseMeta}}},
	}

	merged := MergeFindings(findings)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if merged[0].Severity != SeverityHigh {
		t.Errorf("expected merged severity to take the higher rank (high), got %s", merged[0].Severity)
	}
	if merged[0].Confidence != 0.8 {
		t.Errorf("expected merged confidence to take the max (0.8), got %v", merged[0].Confidence)
	}
	if len(merged[0].Evidence) != 2 {
		t.Errorf("expected evidence from both findings to be unioned, got %d entries", len(merged[0].Evidence))
	}
}

func TestMergeFindings_DistinctIdentitiesUnaffected(t *testing.T) {
	findings := []Finding{
		{AssetID: uuid.New(), DetectorID: "d"},
		{AssetID: uuid.New(), DetectorID: "d"},
	}
	if merged := MergeFindings(findings); len(merged) != 2 {
		t.Fatalf("expected 2 distinct findings to remain distinct, got %d", len(merged))
	}
}

func TestMergeFindings_EndpointScopeKeepsIdentityDistinct(t *testing.T) {
	assetID := uuid.New()
	ep1, ep2 := uuid.New(), uuid.New()
	findings := []Finding{
		{AssetID: assetID, EndpointID: &ep1, DetectorID: "d"},
		{AssetID: assetID, EndpointID: &ep2, DetectorID: "d"},
	}
	// Same asset+detector but different endpoints: two genuinely different
	// findings, not a duplicate (phase8.md §44).
	if merged := MergeFindings(findings); len(merged) != 2 {
		t.Fatalf("expected findings on distinct endpoints to remain distinct, got %d", len(merged))
	}
}

func TestIdentityKey_Deterministic(t *testing.T) {
	assetID := uuid.New()
	first := IdentityKey(assetID, nil, "d")
	second := IdentityKey(assetID, nil, "d")
	if first != second {
		t.Fatal("expected identical inputs to produce identical keys")
	}
	epID := uuid.New()
	if IdentityKey(assetID, &epID, "d") == first {
		t.Fatal("expected endpoint-scoped key to differ from asset-scoped key")
	}
}
