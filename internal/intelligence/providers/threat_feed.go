package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"ai-surface-platform/internal/httpclient"
	"ai-surface-platform/internal/intelligence"
)

const threatFeedProviderVersion = "1"

// ThreatFeedConfig configures ThreatFeedProvider. BaseURL is
// operator-supplied (no specific vendor is hard-coded — this platform
// makes no claim of integrating any named commercial feed); APIKeyEnv
// names the environment variable holding the credential — the credential
// itself is never read from configuration or stored anywhere
// (phase10.md §26).
type ThreatFeedConfig struct {
	BaseURL           string
	APIKeyEnv         string
	RequestsPerSecond float64
	MaxRetries        int
}

// ThreatFeedProvider is the one external, network-backed provider
// (phase10.md §17/§29). It is a Capability
// CapabilityThreatFeed provider — internal/intelligence.Engine only ever
// queries it when Config.ExternalEnrichmentEnabled is true (phase10.md
// §29/§30/§73), on top of this provider being individually enabled in
// the registry. An unconfigured BaseURL/APIKeyEnv makes every Lookup
// call return a clear configuration error rather than silently
// succeeding with no data.
type ThreatFeedProvider struct {
	client  *httpclient.Client
	cfg     ThreatFeedConfig
	limiter *rateLimiter
}

// NewThreatFeedProvider builds a ThreatFeedProvider. client is reused
// from the platform's existing HTTP transport (internal/httpclient) —
// phase10.md §1's "do not create duplicate infrastructure".
func NewThreatFeedProvider(client *httpclient.Client, cfg ThreatFeedConfig) *ThreatFeedProvider {
	return &ThreatFeedProvider{client: client, cfg: cfg, limiter: newRateLimiter(cfg.RequestsPerSecond)}
}

// ID implements intelligence.Provider.
func (p *ThreatFeedProvider) ID() string { return "threat_feed" }

// Name implements intelligence.Provider.
func (p *ThreatFeedProvider) Name() string { return "External Threat Feed" }

// Version implements intelligence.Provider.
func (p *ThreatFeedProvider) Version() string { return threatFeedProviderVersion }

// Capabilities implements intelligence.Provider.
func (p *ThreatFeedProvider) Capabilities() []intelligence.Capability {
	return []intelligence.Capability{intelligence.CapabilityThreatFeed, intelligence.CapabilityReputation}
}

// feedResponse is the minimal generic response shape this provider
// understands. Every field is treated as untrusted external data
// (phase10.md §68): unrecognized verdict/confidence strings fall back to
// "unknown"/"unknown" rather than being trusted verbatim, and Reference/
// Tags are stored as plain strings only, never rendered as HTML or
// executed.
type feedResponse struct {
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence"`
	Category   string   `json:"category"`
	Reference  string   `json:"reference"`
	Tags       []string `json:"tags"`
}

var validFeedVerdicts = map[string]intelligence.Verdict{
	"benign": intelligence.VerdictBenign, "suspicious": intelligence.VerdictSuspicious,
	"malicious": intelligence.VerdictMalicious, "unknown": intelligence.VerdictUnknown,
}

var validFeedConfidences = map[string]intelligence.Confidence{
	"low": intelligence.ConfidenceLow, "medium": intelligence.ConfidenceMedium,
	"high": intelligence.ConfidenceHigh, "unknown": intelligence.ConfidenceUnknown,
}

// Lookup issues one bounded, rate-limited GET request per call — never an
// unbounded batch of its own (phase10.md §27/§28/§69/§70). ctx's
// deadline plus the caller-supplied Engine.Config.ProviderTimeout is the
// only timeout in effect; this provider adds no further retry beyond a
// single bounded Retry-After wait on HTTP 429 (phase10.md §27's "respect
// HTTP 429 / Retry-After").
func (p *ThreatFeedProvider) Lookup(ctx context.Context, indicator intelligence.Indicator) ([]intelligence.Record, error) {
	if p.cfg.BaseURL == "" {
		return nil, fmt.Errorf("threat feed provider is not configured (intelligence.threat_feed.base_url is empty)")
	}
	if p.cfg.APIKeyEnv == "" {
		return nil, fmt.Errorf("threat feed provider is not configured (intelligence.threat_feed.api_key_env is empty)")
	}
	apiKey := os.Getenv(p.cfg.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("environment variable %s is not set", p.cfg.APIKeyEnv)
	}

	if !awaitLimiter(ctx, p.limiter) {
		return nil, ctx.Err()
	}

	reqURL := fmt.Sprintf("%s?type=%s&indicator=%s", p.cfg.BaseURL, url.QueryEscape(string(indicator.Type)), url.QueryEscape(indicator.Value))
	headers := http.Header{"Authorization": []string{"Bearer " + apiKey}, "Accept": []string{"application/json"}}

	resp, err := p.client.Get(ctx, reqURL, headers)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := retryAfterDuration(resp.Headers.Get("Retry-After"))
		if wait <= 0 || wait > 30*time.Second {
			return nil, fmt.Errorf("rate limited (HTTP 429)")
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		resp, err = p.client.Get(ctx, reqURL, headers)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("threat feed authentication failed (HTTP %d) — never retried", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threat feed returned HTTP %d", resp.StatusCode)
	}

	var parsed feedResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("parsing threat feed response: %w", err)
	}

	verdict, ok := validFeedVerdicts[parsed.Verdict]
	if !ok {
		verdict = intelligence.VerdictUnknown
	}
	confidence, ok := validFeedConfidences[parsed.Confidence]
	if !ok {
		confidence = intelligence.ConfidenceUnknown
	}

	return []intelligence.Record{{
		Indicator: indicator, SourceType: "threat_feed",
		Verdict: verdict, Confidence: confidence, Category: intelligence.Category(parsed.Category),
		RetrievedAt: time.Now().UTC(), SourceReference: parsed.Reference, Tags: parsed.Tags,
		NormalizedData: map[string]any{"raw_verdict": parsed.Verdict, "raw_confidence": parsed.Confidence},
	}}, nil
}

func retryAfterDuration(header string) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(header); err == nil {
		return time.Until(when)
	}
	return 0
}

// rateLimiter paces requests to at most requestsPerSecond per second — a
// safety/stability control, not stealth/evasion timing, mirroring every
// discovery engine's local rateLimiter (internal/discovery/dns,
// internal/discovery/network, internal/discovery/endpoint). nil (from
// requestsPerSecond <= 0) means unlimited.
type rateLimiter struct {
	ticker *time.Ticker
	C      <-chan time.Time
}

func newRateLimiter(requestsPerSecond float64) *rateLimiter {
	if requestsPerSecond <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / requestsPerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	t := time.NewTicker(interval)
	return &rateLimiter{ticker: t, C: t.C}
}

func awaitLimiter(ctx context.Context, limiter *rateLimiter) bool {
	if limiter == nil {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-limiter.C:
		return true
	}
}
