package rule

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func validRule() Rule {
	return Rule{
		TargetID: uuid.New(), Name: "repeated_failed_authentication",
		Status: StatusDraft, RuleType: TypeThreshold,
		Severity: SeverityMedium, Confidence: ConfidenceMedium, CreatedBy: "analyst1",
	}
}

func TestRule_Validate(t *testing.T) {
	if err := validRule().Validate(); err != nil {
		t.Fatalf("expected valid rule, got %v", err)
	}

	noName := validRule()
	noName.Name = ""
	if err := noName.Validate(); err == nil {
		t.Fatal("expected error for missing name")
	}

	badType := validRule()
	badType.RuleType = "arbitrary_code"
	if err := badType.Validate(); err == nil {
		t.Fatal("expected error for unrecognized rule type")
	}
}

func TestStatus_Active(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{StatusDraft, false}, {StatusEnabled, true}, {StatusDisabled, false}, {StatusDeprecated, false},
	}
	for _, c := range cases {
		if got := c.status.Active(); got != c.want {
			t.Errorf("Status(%s).Active() = %v, want %v", c.status, got, c.want)
		}
	}
}

func validVersion() Version {
	return Version{
		RuleID: uuid.New(), Version: 1, Definition: `{"event_type":"finding"}`,
		DefinitionHash: "abc123", EventSchemaVersion: DefaultEventSchemaVersion, CreatedBy: "analyst1",
	}
}

func TestVersion_Validate(t *testing.T) {
	if err := validVersion().Validate(); err != nil {
		t.Fatalf("expected valid version, got %v", err)
	}
	zeroVersion := validVersion()
	zeroVersion.Version = 0
	if err := zeroVersion.Validate(); err == nil {
		t.Fatal("expected error for version < 1")
	}
}

func TestDetectionMatch_Validate_RequiresExplanation(t *testing.T) {
	m := DetectionMatch{
		TargetID: uuid.New(), RuleID: uuid.New(), RuleVersion: 1, Fingerprint: "fp1",
		FirstObservedAt: time.Now(), Severity: SeverityHigh, Confidence: ConfidenceHigh, Status: MatchOpen,
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing explanation — a match is never persisted without one")
	}
	m.Explanation = "7 failed logins for alice from 1.2.3.4 within 5 minutes"
	if err := m.Validate(); err != nil {
		t.Fatalf("expected valid match, got %v", err)
	}
}

func TestSuppression_Active(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	indefinite := Suppression{ExpiresAt: nil}
	if !indefinite.Active(now) {
		t.Error("expected indefinite suppression to be active")
	}

	notYetExpired := Suppression{ExpiresAt: &future}
	if !notYetExpired.Active(now) {
		t.Error("expected not-yet-expired suppression to be active")
	}

	expired := Suppression{ExpiresAt: &past}
	if expired.Active(now) {
		t.Error("expected expired suppression to be inactive")
	}

	removedAt := now
	removed := Suppression{ExpiresAt: &future, RemovedAt: &removedAt}
	if removed.Active(now) {
		t.Error("expected removed suppression to be inactive regardless of expiry")
	}
}

func TestAlert_Validate(t *testing.T) {
	a := Alert{
		TargetID: uuid.New(), DetectionMatchID: uuid.New(), Title: "Repeated failed logins for alice",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Status: AlertOpen,
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("expected valid alert, got %v", err)
	}
}
