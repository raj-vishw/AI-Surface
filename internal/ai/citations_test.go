package ai

import "testing"

func TestValidateCitations_RemovesFabricated(t *testing.T) {
	valid := map[string]bool{"[alert:A-1]": true}
	content := "The alert fired [alert:A-1] and is related to [event:FAKE-99]."

	cleaned, removed := ValidateCitations(content, valid)

	if got := ExtractCitations(cleaned); len(got) != 1 || got[0] != "[alert:A-1]" {
		t.Errorf("cleaned content citations = %v, want only [alert:A-1]", got)
	}
	if len(removed) != 1 || removed[0] != "[event:FAKE-99]" {
		t.Errorf("removed = %v, want [event:FAKE-99]", removed)
	}
}

func TestValidateCitations_DuplicateFabricatedRemovedOnce(t *testing.T) {
	valid := map[string]bool{}
	content := "[finding:X] appears twice [finding:X]."
	_, removed := ValidateCitations(content, valid)
	if len(removed) != 1 {
		t.Errorf("removed = %v, want exactly one entry despite two occurrences", removed)
	}
}

func TestValidateCitations_NoCitationsIsNoOp(t *testing.T) {
	content := "There is nothing to cite here."
	cleaned, removed := ValidateCitations(content, map[string]bool{})
	if cleaned != content {
		t.Errorf("cleaned = %q, want unchanged %q", cleaned, content)
	}
	if len(removed) != 0 {
		t.Errorf("removed = %v, want none", removed)
	}
}

func TestExtractCitations_DoesNotInventTokens(t *testing.T) {
	content := "Severity is [high] but only [alert:A-1] is a real citation."
	got := ExtractCitations(content)
	if len(got) != 1 || got[0] != "[alert:A-1]" {
		t.Errorf("ExtractCitations = %v, want only [alert:A-1] (bracket without type:id is not a citation)", got)
	}
}
