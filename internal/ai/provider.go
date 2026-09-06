package ai

import (
	"context"
	"time"
)

// Request is what Assistant asks a Provider to generate from — already a
// fully-built, guardrail-wrapped prompt (see prompt.go). A Provider never
// sees raw Fact/Context values; it only ever sees the two rendered prompt
// strings, so a provider implementation cannot accidentally bypass
// redaction or the trust-boundary framing applied when the prompt was
// built.
type Request struct {
	TaskType TaskType

	// SystemPrompt/UserPrompt are the two rendered prompt strings (see
	// BuildPrompt). SystemPrompt is never echoed back to an analyst
	// (phase13.md §9).
	SystemPrompt string
	UserPrompt   string

	MaxOutputTokens int
	Temperature     float64
}

// ProviderResponse is a Provider's raw output, before citation validation,
// unsupported-claim rewriting, or confidence derivation are applied by
// Assistant.
type ProviderResponse struct {
	Content string
	Model   string

	InputTokens  int
	OutputTokens int
	Latency      time.Duration
}

// Provider is the pluggable interface every AI backend implements
// (phase13.md §3) — this platform is never hard-coded to one vendor.
// Implementations must not block indefinitely: Generate must respect
// ctx's deadline/cancellation (phase13.md §56/§57's "AI requests must have
// a finite timeout").
type Provider interface {
	// Name identifies this provider for audit/config purposes (e.g.
	// "mock", "openai").
	Name() string
	Generate(ctx context.Context, req Request) (ProviderResponse, error)
}
