package intelligence

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func validRecord() Record {
	return Record{
		TargetID: uuid.New(), IndicatorType: IndicatorDomain, IndicatorValue: "example.com",
		ProviderID: "local", SourceType: "local", Verdict: VerdictUnknown, Confidence: ConfidenceHigh,
		RetrievedAt: time.Now(),
	}
}

func TestRecord_Validate(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("expected valid record, got %v", err)
	}

	missingTarget := validRecord()
	missingTarget.TargetID = uuid.Nil
	if err := missingTarget.Validate(); err == nil {
		t.Fatal("expected error for missing target_id")
	}

	badSourceType := validRecord()
	badSourceType.SourceType = "made_up"
	if err := badSourceType.Validate(); err == nil {
		t.Fatal("expected error for unrecognized source_type")
	}

	badVerdict := validRecord()
	badVerdict.Verdict = "definitely_malicious"
	if err := badVerdict.Validate(); err == nil {
		t.Fatal("expected error for unrecognized verdict")
	}
}

func TestRecord_Fresh(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	noExpiry := Record{}
	if !noExpiry.Fresh(now) {
		t.Error("nil expiration should always be fresh")
	}
	expired := Record{Expiration: &past}
	if expired.Fresh(now) {
		t.Error("expected expired record to not be fresh")
	}
	notExpired := Record{Expiration: &future}
	if !notExpired.Fresh(now) {
		t.Error("expected non-expired record to be fresh")
	}
}

func TestNormalizeDomain(t *testing.T) {
	if got := NormalizeDomain("EXAMPLE.com."); got != "example.com" {
		t.Errorf("NormalizeDomain = %q, want example.com", got)
	}
}
