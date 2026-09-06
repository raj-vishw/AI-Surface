// Package mock implements internal/ai.Provider without any external
// dependency (phase13.md §59: "do not require an external API for the
// test suite"). It is also this platform's honest local/offline mode: by
// default it narrates the deterministic StructuredResult it is asked to
// produce output from, verbatim — a truthful evidence digest rather than
// a fabricated free-form analysis, which is exactly right for a
// provider that does no real natural-language reasoning of its own.
package mock

import (
	"context"
	"time"

	"ai-recon-platform/internal/ai"
)

// Provider is internal/ai.Provider's mock/offline implementation.
type Provider struct {
	// ResponseFunc, when set, overrides the default deterministic
	// narration entirely — used by tests that need to exercise
	// Assistant's guardrails (fabricated citations, unsupported claims,
	// attribution) against a controlled raw response.
	ResponseFunc func(ai.Request) (ai.ProviderResponse, error)
}

// New returns a Provider using the default deterministic narration.
func New() *Provider { return &Provider{} }

// Name implements ai.Provider.
func (*Provider) Name() string { return "mock" }

// Generate implements ai.Provider. It never blocks on external I/O, so it
// still respects ctx's cancellation for consistency with a real provider.
func (p *Provider) Generate(ctx context.Context, req ai.Request) (ai.ProviderResponse, error) {
	if err := ctx.Err(); err != nil {
		return ai.ProviderResponse{}, err
	}
	start := time.Now()
	if p.ResponseFunc != nil {
		resp, err := p.ResponseFunc(req)
		if resp.Model == "" {
			resp.Model = "mock-deterministic"
		}
		if resp.Latency == 0 {
			resp.Latency = time.Since(start)
		}
		return resp, err
	}

	// Default behavior: the user prompt already contains the
	// deterministic <data> block built from Context — this mock has no
	// real language model behind it, so it narrates that data plainly
	// rather than inventing analysis. Assistant.Run always has its own
	// StructuredResult.Render() fallback ready in case this content fails
	// citation validation, but since this content only ever repeats
	// citations it was itself given, it always validates cleanly.
	content := "Evidence-grounded summary (offline mode — no external AI provider configured):\n\n" + req.UserPrompt

	return ai.ProviderResponse{
		Content: content, Model: "mock-deterministic",
		InputTokens: len(req.SystemPrompt) + len(req.UserPrompt), OutputTokens: len(content),
		Latency: time.Since(start),
	}, nil
}
