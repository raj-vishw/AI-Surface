package reporting

import (
	"strings"
	"testing"
)

func TestEscapeCSVValue_NeutralizesFormulaPrefixes(t *testing.T) {
	cases := []string{"=SUM(A1:A2)", "+123", "-123", "@example", "\tevil", "\revil"}
	for _, c := range cases {
		got := EscapeCSVValue(c)
		if got == c {
			t.Errorf("EscapeCSVValue(%q) was not modified — CSV injection risk", c)
		}
		if !strings.HasPrefix(got, "'") {
			t.Errorf("EscapeCSVValue(%q) = %q, want a leading single quote", c, got)
		}
	}
}

func TestEscapeCSVValue_LeavesOrdinaryTextAlone(t *testing.T) {
	cases := []string{"example.com", "a-1", "a normal sentence.", "", "café"}
	for _, c := range cases {
		if got := EscapeCSVValue(c); got != c {
			t.Errorf("EscapeCSVValue(%q) = %q, want unchanged", c, got)
		}
	}
}

func TestEncodeCSV_HandlesCommasNewlinesAndUnicode(t *testing.T) {
	headers := []string{"title", "description"}
	rows := [][]string{
		{"finding, with a comma", "line one\nline two"},
		{"unicode café ☃", "plain"},
	}
	out, err := EncodeCSV(headers, rows)
	if err != nil {
		t.Fatalf("EncodeCSV: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"finding, with a comma"`) {
		t.Errorf("comma value not properly quoted: %q", s)
	}
	if !strings.Contains(s, "café") || !strings.Contains(s, "☃") {
		t.Errorf("unicode not preserved: %q", s)
	}
}

func TestEncodeCSV_RejectsMismatchedRowLength(t *testing.T) {
	_, err := EncodeCSV([]string{"a", "b"}, [][]string{{"only one"}})
	if err == nil {
		t.Fatal("expected an error for a row with the wrong number of columns")
	}
}

func TestEncodeCSV_EscapesInjectionInDataCells(t *testing.T) {
	out, err := EncodeCSV([]string{"value"}, [][]string{{"=cmd|'/c calc'!A1"}})
	if err != nil {
		t.Fatalf("EncodeCSV: %v", err)
	}
	if !strings.Contains(string(out), "'=cmd") {
		t.Errorf("formula-injection cell was not escaped: %q", out)
	}
}
