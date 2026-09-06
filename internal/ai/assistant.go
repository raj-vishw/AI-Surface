package ai

import (
	"context"
	"fmt"
	"time"
)

// Result is one completed AI task's full outcome — everything
// internal/service/ai needs to persist an internal/domain/ai.Response and
// return something useful to a CLI command.
type Result struct {
	TaskType TaskType

	Content    string
	Structured StructuredResult

	Model    string
	Provider string

	PromptVersion string
	ContextHash   string
	ResponseHash  string

	Confidence Confidence
	Citations  []string

	InputTokens  int
	OutputTokens int
	Latency      time.Duration

	Truncated bool

	// FabricatedCitationsRemoved/UnsupportedClaimsRewritten/
	// AttributionRejected/UsedFallback surface exactly what guardrail
	// activity occurred, for audit logging (phase13.md §53/§96) — never
	// silently swallowed.
	FabricatedCitationsRemoved []string
	UnsupportedClaimsRewritten int
	AttributionRejected        bool
	UsedFallback               bool
}

// Assistant orchestrates one AI task end to end: build the structured
// facts deterministically, render a prompt, call a Provider, validate the
// output, and derive confidence (phase13.md §2's Generate contract,
// wrapped with every guardrail phase13.md §14-18/§38/§42-43 requires).
type Assistant struct {
	MaxOutputTokens int
	Temperature     float64
}

// NewAssistant returns an Assistant with safe defaults.
func NewAssistant() *Assistant {
	return &Assistant{MaxOutputTokens: 2000, Temperature: 0.2}
}

// Run executes one task against ctx using provider, optionally guided by
// an analyst's own free-form instructions (chat; empty for a fixed task).
// build is the task-specific deterministic structured-result builder from
// investigator.go/summarizer.go — passed in rather than switched on
// internally so callers (and tests) can exercise one task in isolation.
func (a *Assistant) Run(goCtx context.Context, provider Provider, task TaskType, evidence Context, instructions string, build func(Context) StructuredResult) (Result, error) {
	if provider == nil {
		return Result{}, fmt.Errorf("no AI provider configured")
	}

	structured := build(evidence)
	fallback := structured.Render()

	system, user := BuildPrompt(task, evidence, instructions)

	req := Request{
		TaskType: task, SystemPrompt: system, UserPrompt: user,
		MaxOutputTokens: a.MaxOutputTokens, Temperature: a.Temperature,
	}

	resp, err := provider.Generate(goCtx, req)
	if err != nil {
		return Result{}, fmt.Errorf("AI provider %q failed: %w", provider.Name(), err)
	}

	outcome := ValidateOutput(resp.Content, evidence.CitationSet(), fallback)

	citations := ExtractCitations(outcome.Content)
	confidence := DeriveConfidence(len(evidence.Facts), evidence.Truncated, len(outcome.FabricatedCitationsRemoved))

	return Result{
		TaskType: task, Content: outcome.Content, Structured: structured,
		Model: resp.Model, Provider: provider.Name(),
		PromptVersion: task.PromptVersion(), ContextHash: evidence.Hash(), ResponseHash: ResponseHash(outcome.Content),
		Confidence: confidence, Citations: dedupeStrings(citations),
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens, Latency: resp.Latency,
		Truncated:                  evidence.Truncated,
		FabricatedCitationsRemoved: outcome.FabricatedCitationsRemoved, UnsupportedClaimsRewritten: outcome.UnsupportedClaimsRewritten,
		AttributionRejected: outcome.AttributionRejected, UsedFallback: outcome.UsedFallback,
	}, nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
