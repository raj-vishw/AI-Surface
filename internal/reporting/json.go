package reporting

import (
	"encoding/json"
	"time"
)

// Envelope is the stable JSON export shape every report export uses
// (phase14.md §44): metadata, generation time, version, the report's own
// data (its sections), and the evidence references it cites — never a
// bare, unversioned data dump.
//
// Go's encoding/json escapes '<', '>', and '&' to </>/& by
// default (json.Marshal's SetEscapeHTML defaults to true) — this
// platform renders no HTML anywhere, but this default already means an
// exported report containing a telemetry-derived string like
// "<script>alert(1)</script>" is emitted as inert escaped text, never as
// live markup, satisfying phase14.md §94's "do not render raw HTML from
// telemetry" for the JSON export path with no extra code (see
// json_test.go's TestEncodeJSON_EscapesHTMLByDefault).
type Envelope struct {
	Metadata      Metadata  `json:"metadata"`
	GeneratedAt   time.Time `json:"generated_at"`
	ReportVersion int       `json:"report_version"`
	Data          Sections  `json:"data"`
	// EvidenceReferences is the flat citation-token list (phase14.md §44)
	// — derived from Data.AllCitations(), kept for a reader that only
	// wants the reference tokens without walking every section.
	EvidenceReferences []string `json:"evidence_references"`
	// Refs is the same evidence, structured (type/id/timestamp) rather
	// than a bare token string — internal/service/reporting's evidence-
	// package builder uses this to construct a manifest without a second
	// round of database lookups.
	Refs []EvidenceRef `json:"refs,omitempty"`
}

// Metadata carries a report's identifying/audit fields (phase14.md §38).
type Metadata struct {
	ReportType    string  `json:"report_type"`
	TargetID      string  `json:"target_id"`
	SubjectID     string  `json:"subject_id,omitempty"`
	GeneratedBy   string  `json:"generated_by"`
	Status        string  `json:"status"`
	ContentHash   string  `json:"content_hash"`
	Provider      *string `json:"provider,omitempty"`
	Model         *string `json:"model,omitempty"`
	PromptVersion *string `json:"prompt_version,omitempty"`
}

// EncodeJSON renders e as indented JSON.
func EncodeJSON(e Envelope) ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
