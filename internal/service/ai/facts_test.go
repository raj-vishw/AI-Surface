package ai

import (
	"testing"
	"time"

	"github.com/google/uuid"

	domainfinding "ai-recon-platform/internal/domain/finding"
	domainrule "ai-recon-platform/internal/domain/rule"
)

func TestFindingToFact_RedactsSecretsInTitle(t *testing.T) {
	f := domainfinding.Finding{
		ID: uuid.New(), Title: "Response leaked password=hunter2", Severity: domainfinding.SeverityHigh,
		Status: domainfinding.StatusOpen, Category: domainfinding.CategoryAuthentication, LastSeen: time.Now(),
	}
	fact := findingToFact(f)
	if fact.ID != f.ID.String() {
		t.Errorf("fact.ID = %q, want %q", fact.ID, f.ID.String())
	}
	if containsPassword(fact.Summary) {
		t.Errorf("finding fact summary was not redacted: %q", fact.Summary)
	}
}

func TestAlertToFact_NeverInventsID(t *testing.T) {
	id := uuid.New()
	a := domainrule.Alert{ID: id, Title: "Suspicious login pattern", Severity: domainrule.SeverityHigh, Confidence: domainrule.ConfidenceHigh, Status: domainrule.AlertOpen, LastObservedAt: time.Now()}
	fact := alertToFact(a)
	if fact.ID != id.String() {
		t.Errorf("fact.ID = %q, want the alert's own id %q", fact.ID, id.String())
	}
}

func TestAttrs_DeterministicOrdering(t *testing.T) {
	m := map[string]string{"z": "1", "a": "2", "m": "3"}
	out1 := attrs(m)
	out2 := attrs(m)
	if out1 != out2 {
		t.Errorf("attrs is not deterministic: %q vs %q", out1, out2)
	}
	if out1 != " (a=2, m=3, z=1)" {
		t.Errorf("attrs = %q, want sorted-key form", out1)
	}
}

func containsPassword(s string) bool {
	const needle = "hunter2"
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
