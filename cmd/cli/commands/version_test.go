package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionCommandTextOutput(t *testing.T) {
	cmd := NewVersionCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if !strings.Contains(buf.String(), "ai-recon") {
		t.Errorf("expected output to contain \"ai-recon\", got %q", buf.String())
	}
}

func TestVersionCommandJSONOutput(t *testing.T) {
	cmd := NewVersionCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v (output: %s)", err, buf.String())
	}
	if _, ok := payload["version"]; !ok {
		t.Errorf("expected JSON output to contain a \"version\" field, got %v", payload)
	}
}
