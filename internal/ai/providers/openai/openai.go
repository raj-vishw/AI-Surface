// Package openai implements internal/ai.Provider against an
// OpenAI-compatible Chat Completions endpoint (phase13.md §3's "the
// project's selected production provider if already configured"). This
// is deliberately generic rather than vendor-specific: the same client
// works against OpenAI itself, an Azure OpenAI-compatible proxy, or a
// self-hosted OpenAI-compatible server (vLLM, Ollama, llama.cpp) — no
// vendor is hard-coded, matching internal/intelligence/providers.
// ThreatFeedProvider's identical "operator supplies base_url" discipline
// from Phase 10.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"ai-surface-platform/internal/ai"
)

// Config configures Provider. APIKeyEnv names an environment variable —
// the key itself is never accepted directly in configuration
// (phase13.md §4/§5: "never hard-code API keys, tokens, credentials").
type Config struct {
	Endpoint  string // e.g. "https://api.openai.com/v1/chat/completions"
	Model     string
	APIKeyEnv string
	Timeout   time.Duration
}

// Provider is internal/ai.Provider's OpenAI-compatible implementation.
type Provider struct {
	cfg    Config
	client *http.Client
}

// New returns a Provider. It does not read or validate the API key at
// construction time — a missing key surfaces as a clear Generate-time
// error (phase13.md §58: "if the provider is unavailable, return a clear
// error"), never a silent no-op.
func New(cfg Config) *Provider {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Provider{cfg: cfg, client: &http.Client{Timeout: timeout}}
}

// Name implements ai.Provider.
func (*Provider) Name() string { return "openai" }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type chatResponse struct {
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   chatUsage    `json:"usage"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Generate implements ai.Provider. It always respects ctx's
// deadline/cancellation, and never retries internally — bounded retries
// are internal/service/ai's responsibility (see internal/ai's retry
// wrapper), so this stays a single, clearly-erroring HTTP call.
func (p *Provider) Generate(ctx context.Context, req ai.Request) (ai.ProviderResponse, error) {
	if strings.TrimSpace(p.cfg.Endpoint) == "" {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: endpoint is not configured")
	}
	apiKey := ""
	if p.cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(p.cfg.APIKeyEnv)
	}
	if apiKey == "" {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: environment variable %q is not set", p.cfg.APIKeyEnv)
	}

	body, err := json.Marshal(chatRequest{
		Model: p.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		MaxTokens: req.MaxOutputTokens, Temperature: req.Temperature,
	})
	if err != nil {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	start := time.Now()
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: request failed: %w", err)
	}
	defer httpResp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20)) // 4 MiB response cap
	if err != nil {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: reading response: %w", err)
	}

	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: malformed response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("HTTP %d", httpResp.StatusCode)
		if parsed.Error != nil && parsed.Error.Message != "" {
			msg += ": " + parsed.Error.Message
		}
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: %s", msg)
	}
	if len(parsed.Choices) == 0 {
		return ai.ProviderResponse{}, fmt.Errorf("openai provider: response contained no choices")
	}

	return ai.ProviderResponse{
		Content:     parsed.Choices[0].Message.Content,
		Model:       firstNonEmpty(parsed.Model, p.cfg.Model),
		InputTokens: parsed.Usage.PromptTokens, OutputTokens: parsed.Usage.CompletionTokens,
		Latency: time.Since(start),
	}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
