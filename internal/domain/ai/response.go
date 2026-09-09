package ai

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Response is a persisted record of one AI-generated answer (phase13.md
// §7). It is explicitly never treated as verified fact — Content is
// advisory, analyst-reviewed output, exactly like a draft correlation or
// attack chain is analyst-reviewed before confirmation (phase13.md §7's
// own "do not treat AI-generated content as verified fact").
type Response struct {
	ID        uuid.UUID
	RequestID uuid.UUID

	Content string

	Model    string
	Provider string

	// PromptVersion mirrors the originating Request's — kept here too so a
	// response remains self-describing even if queried independently
	// (phase13.md §98).
	PromptVersion string

	// Confidence is the AI's own confidence in this interpretation — see
	// internal/ai.Confidence's doc comment for the "not probability of
	// attack" rule (phase13.md §40/§41).
	Confidence Confidence

	// Citations lists every evidence reference token
	// (e.g. "finding:<uuid>") this response's Content actually cites,
	// after validation has removed any that don't exist in the supplied
	// context (phase13.md §14/§15) — never a fabricated id.
	Citations []string

	// ResponseHash is an integrity-verification hash of Content
	// (phase13.md §101).
	ResponseHash string

	// Structured carries the same Observed/Inferred/Unknown/EvidenceGaps/
	// NextSteps/Questions/Citations breakdown internal/ai.StructuredResult
	// builds for every task (see internal/ai/investigator.go) — persisted
	// alongside the rendered Content so a later reader (the REST API, a
	// future UI) can render the section-by-section Trust UI directly
	// rather than re-deriving it from prose. A generic map, the same
	// "domain package never imports the engine package" boundary
	// Finding.Metadata/Asset.Metadata already establish — this package
	// has no dependency on internal/ai's StructuredResult type.
	Structured map[string]any

	InputTokens  int
	OutputTokens int
	LatencyMS    int64

	CreatedAt time.Time
}

// Validate checks that r is internally consistent.
func (r Response) Validate() error {
	var errs validation.Errors

	if r.RequestID == uuid.Nil {
		errs = errs.Add("request_id", "must not be empty")
	}
	if !trimmedNotEmpty(r.Content) {
		errs = errs.Add("content", "must not be empty")
	}
	if !trimmedNotEmpty(r.Model) {
		errs = errs.Add("model", "must not be empty")
	}
	if !trimmedNotEmpty(r.Provider) {
		errs = errs.Add("provider", "must not be empty")
	}
	if !r.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if r.InputTokens < 0 {
		errs = errs.Add("input_tokens", "must not be negative")
	}
	if r.OutputTokens < 0 {
		errs = errs.Add("output_tokens", "must not be negative")
	}
	if r.LatencyMS < 0 {
		errs = errs.Add("latency_ms", "must not be negative")
	}

	return errs.ErrOrNil()
}
