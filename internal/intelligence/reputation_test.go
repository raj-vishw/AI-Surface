package intelligence

import (
	"testing"
	"time"
)

func TestAggregate_ConflictPreserved_NoAutoConfirmedMalicious(t *testing.T) {
	records := []Record{
		{ProviderID: "a", Verdict: VerdictMalicious, Confidence: ConfidenceHigh},
		{ProviderID: "b", Verdict: VerdictBenign, Confidence: ConfidenceHigh},
	}
	got := Aggregate(records, nil)

	if got.ConflictingSources == 0 {
		t.Fatalf("expected conflict to be preserved, got %+v", got)
	}
	if len(got.Records) != 2 {
		t.Fatalf("expected both source records preserved, got %d", len(got.Records))
	}
	// A bare 1-vs-1 tie must never headline "malicious" — conservative
	// tie-break toward the less severe verdict (phase10.md §98).
	if got.Verdict == VerdictMalicious {
		t.Fatalf("a 1-vs-1 tie must not resolve to malicious, got %s", got.Verdict)
	}
}

func TestAggregate_MajorityWins(t *testing.T) {
	records := []Record{
		{ProviderID: "a", Verdict: VerdictMalicious, Confidence: ConfidenceHigh},
		{ProviderID: "b", Verdict: VerdictMalicious, Confidence: ConfidenceMedium},
		{ProviderID: "c", Verdict: VerdictBenign, Confidence: ConfidenceLow},
	}
	got := Aggregate(records, nil)
	if got.Verdict != VerdictMalicious {
		t.Fatalf("expected majority verdict malicious, got %s", got.Verdict)
	}
	if got.SupportingSources != 2 || got.ConflictingSources != 1 {
		t.Fatalf("expected 2 supporting / 1 conflicting, got %d/%d", got.SupportingSources, got.ConflictingSources)
	}
}

func TestAggregate_AllUnknown(t *testing.T) {
	got := Aggregate([]Record{{ProviderID: "a", Verdict: VerdictUnknown}}, nil)
	if got.Verdict != VerdictUnknown {
		t.Fatalf("expected unknown verdict, got %s", got.Verdict)
	}
}

func TestAggregate_Empty(t *testing.T) {
	got := Aggregate(nil, nil)
	if got.Verdict != VerdictUnknown || got.Confidence != ConfidenceUnknown {
		t.Fatalf("expected unknown/unknown for empty input, got %+v", got)
	}
}

func TestAggregate_ConfidenceNeverExceedsBestIndividualSource(t *testing.T) {
	records := []Record{
		{ProviderID: "a", Verdict: VerdictSuspicious, Confidence: ConfidenceLow},
		{ProviderID: "b", Verdict: VerdictSuspicious, Confidence: ConfidenceLow},
	}
	got := Aggregate(records, nil)
	if got.Confidence.Rank() > ConfidenceLow.Rank() {
		t.Fatalf("aggregate confidence %s must not exceed the best individual source's confidence (low)", got.Confidence)
	}
}

func TestFreshRecords(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	notExpired := now.Add(time.Hour)
	past := Record{ProviderID: "a", Expiration: &expired}
	future := Record{ProviderID: "b", Expiration: &notExpired}
	fresh := FreshRecords([]Record{past, future}, now)
	if len(fresh) != 1 {
		t.Fatalf("expected 1 fresh record, got %d", len(fresh))
	}
}
