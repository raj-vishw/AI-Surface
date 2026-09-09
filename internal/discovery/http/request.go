package http

import (
	"net/http"

	"ai-surface-platform/internal/httpclient"
)

// userAgent identifies the platform to the servers it discovers against.
// Discovery must never impersonate a browser or another tool — this is an
// authorized reconnaissance platform, not an evasion tool (phase3.md §6).
const userAgent = "ai-surface-platform/http-discovery"

// buildRequest converts a Candidate into the httpclient.Request that will
// be executed. Every discovery request is GET-only, carries no body, and
// sends no authentication/credentials (phase3.md §6) — the only header set
// is a truthful User-Agent identifying this platform and a permissive
// Accept header (discovery does not know in advance whether a candidate
// returns HTML, JSON, or plain text).
func buildRequest(c Candidate) httpclient.Request {
	headers := http.Header{}
	headers.Set("User-Agent", userAgent)
	headers.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")

	return httpclient.Request{
		Method:  c.Method,
		URL:     c.URL,
		Headers: headers,
	}
}
