package investigation

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleBundle() ExportBundle {
	return ExportBundle{
		Summary:  Summary{Title: "Suspicious API Surface Change", Status: "open", Severity: "high"},
		Findings: []exportFinding{{ID: "f1", Title: "Exposed Git metadata", Severity: "high", Status: "open"}},
		Timeline: []exportTimelineEvent{{Timestamp: "2026-01-01T00:00:00Z", Type: "finding_created", Title: "Finding created"}},
		Relationships: []exportRelationship{
			{Type: "same_asset", Status: "confirmed", Score: 30, Explanation: "Both findings affect the same asset."},
		},
		Hypotheses: []exportHypothesis{{Title: "Related to recent deployment", Status: "proposed"}},
		Notes:      []exportNote{{AuthorID: "analyst1", Content: "Checked further.", CreatedAt: "2026-01-01T00:05:00Z"}},
	}
}

func TestExport_JSON(t *testing.T) {
	data, err := Export(sampleBundle(), ExportJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}
	if !strings.Contains(string(data), "Exposed Git metadata") {
		t.Fatal("expected finding title present in JSON export")
	}
}

func TestExport_CSV(t *testing.T) {
	data, err := Export(sampleBundle(), ExportCSV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "finding") || !strings.Contains(s, "Exposed Git metadata") {
		t.Fatalf("expected CSV to contain the finding row, got:\n%s", s)
	}
}

func TestExport_Markdown(t *testing.T) {
	data, err := Export(sampleBundle(), ExportMarkdown)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(data)
	for _, want := range []string{"# Suspicious API Surface Change", "## Findings", "## Timeline", "## Correlations", "## Hypotheses", "## Analyst Notes"} {
		if !strings.Contains(s, want) {
			t.Errorf("expected markdown export to contain %q, got:\n%s", want, s)
		}
	}
}

func TestExport_NeverIncludesSecretFields(t *testing.T) {
	// A structural guarantee, not a redaction test: the export types
	// themselves carry no field capable of holding a credential (no
	// "password", "token", "authorization", "cookie", or "secret" field
	// exists anywhere in exportFinding/exportEvidence/exportNote/etc.).
	data, _ := Export(sampleBundle(), ExportJSON)
	for _, forbidden := range []string{"password", "authorization", "cookie", "secret", "token"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Errorf("export unexpectedly contains %q", forbidden)
		}
	}
}
