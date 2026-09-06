package reporting

import (
	"strings"
	"testing"
	"time"
)

func TestEncodeJSON_EscapesHTMLByDefault(t *testing.T) {
	e := Envelope{
		Metadata:      Metadata{ReportType: "investigation", TargetID: "t1", GeneratedBy: "analyst1", Status: "generated", ContentHash: "h"},
		GeneratedAt:   time.Now(),
		ReportVersion: 1,
		Data:          Sections{{Title: "Findings", Body: "Observed payload: <script>alert(1)</script>"}},
	}
	out, err := EncodeJSON(e)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "<script>") {
		t.Errorf("raw <script> tag survived JSON encoding: %s", s)
	}
	const escapedScriptOpen = "\\u003cscript\\u003e" // the literal 19-character escape sequence json.Marshal emits
	if !strings.Contains(s, escapedScriptOpen) {
		t.Errorf("expected the HTML-escaped form %s, got: %s", escapedScriptOpen, s)
	}
}

func TestEncodeJSON_IncludesRequiredMetadata(t *testing.T) {
	e := Envelope{
		Metadata:      Metadata{ReportType: "executive", TargetID: "t1", GeneratedBy: "analyst1", Status: "approved", ContentHash: "abc"},
		GeneratedAt:   time.Now(),
		ReportVersion: 2,
	}
	out, err := EncodeJSON(e)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	for _, want := range []string{`"report_type"`, `"generated_at"`, `"report_version"`, `"content_hash"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("encoded JSON missing %s: %s", want, out)
		}
	}
}
