package detection

import (
	"context"

	"ai-surface-platform/internal/httpclient"
)

// HTTPFetcher implements SafeActiveFetcher over internal/httpclient.Client
// — the same Phase 1 HTTP client every discovery engine in this project
// already uses (phase8.md §1's "do not create duplicate HTTP clients").
// It performs no scope check of its own: the *client* passed to
// NewHTTPFetcher must already be built with its redirect policy bound to
// the target's scope (via httpclient.Options.AllowRedirectTo, exactly the
// pattern internal/discovery/http.NewClientForScope and
// internal/discovery/endpoint.NewClientForScope establish) — see
// internal/service/detection, the only place that constructs one.
type HTTPFetcher struct {
	client *httpclient.Client
}

// NewHTTPFetcher builds a HTTPFetcher backed by client.
func NewHTTPFetcher(client *httpclient.Client) *HTTPFetcher {
	return &HTTPFetcher{client: client}
}

var _ SafeActiveFetcher = (*HTTPFetcher)(nil)

// Fetch implements SafeActiveFetcher. maxBytes is advisory context for
// evidence bounding only — the client's own configured MaxResponseSize
// (set once, at construction, by internal/service/detection) is what
// actually enforces the response-size limit at the transport level;
// Fetch additionally truncates to maxBytes so one detector's tighter
// excerpt need never depend on another's client-wide setting.
func (f *HTTPFetcher) Fetch(ctx context.Context, rawURL string, maxBytes int) (FetchResult, error) {
	resp, err := f.client.Get(ctx, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	body := resp.Body
	if maxBytes > 0 && len(body) > maxBytes {
		body = body[:maxBytes]
	}
	return FetchResult{StatusCode: resp.StatusCode, ContentType: resp.ContentType, Body: body}, nil
}
