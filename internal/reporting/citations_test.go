package reporting

import (
	"testing"

	"ai-recon-platform/internal/ai"
)

func TestValidateSections_StripsFabricatedCitations(t *testing.T) {
	refs := []EvidenceRef{{Type: "finding", ID: "f1"}}
	sections := Sections{{
		Title:     "Findings",
		Body:      "Observed [finding:f1] and also [finding:FAKE-999].",
		Citations: []string{"[finding:f1]", "[finding:FAKE-999]"},
	}}

	cleaned, removed := ValidateSections(sections, refs)

	if len(removed) != 1 || removed[0] != "[finding:FAKE-999]" {
		t.Errorf("removed = %v, want [finding:FAKE-999]", removed)
	}
	if len(cleaned[0].Citations) != 1 || cleaned[0].Citations[0] != "[finding:f1]" {
		t.Errorf("cleaned Citations = %v, want only [finding:f1]", cleaned[0].Citations)
	}
	for _, c := range ai.ExtractCitations(cleaned[0].Body) {
		if c == "[finding:FAKE-999]" {
			t.Error("fabricated citation survived into cleaned body text")
		}
	}
}

func TestValidateSections_KeepsValidCitations(t *testing.T) {
	refs := []EvidenceRef{{Type: "alert", ID: "a1"}}
	sections := Sections{{Title: "Alerts", Body: "See [alert:a1].", Citations: []string{"[alert:a1]"}}}
	cleaned, removed := ValidateSections(sections, refs)
	if len(removed) != 0 {
		t.Errorf("removed = %v, want none", removed)
	}
	if cleaned[0].Body != sections[0].Body {
		t.Errorf("body changed unexpectedly: %q", cleaned[0].Body)
	}
}

func TestEvidenceRef_TokenMatchesExpectedFormat(t *testing.T) {
	ref := EvidenceRef{Type: "correlation", ID: "c1"}
	if got, want := ref.Token(), "[correlation:c1]"; got != want {
		t.Errorf("Token() = %q, want %q", got, want)
	}
}
