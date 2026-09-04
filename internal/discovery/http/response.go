package http

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/discovery/model"
	domainasset "ai-recon-platform/internal/domain/asset"
	"ai-recon-platform/internal/httpclient"
)

// buildResult converts one candidate's outcome (a completed response or a
// transport error) into a model.Result, running response analysis and AI
// candidate detection along the way.
//
// scope is used here only to *explain* (not enforce — enforcement already
// happened inside httpclient's Options.AllowRedirectTo, before any
// connection to a blocked host was made) whether the final response
// represents a redirect that scope validation refused to follow, so that
// fact is recorded rather than silently discarded (phase3.md §24).
func buildResult(scanID, targetID uuid.UUID, c Candidate, resp *httpclient.Response, reqErr error, cfg Config, scope *ScopeValidator) model.Result {
	result := model.Result{
		ScanID:     scanID,
		TargetID:   targetID,
		Method:     c.Method,
		URL:        c.URL,
		ObservedAt: time.Now().UTC(),
	}

	if reqErr != nil {
		result.Error = reqErr.Error()
		return result
	}

	result.FinalURL = resp.URL
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.ContentType
	result.ContentLength = resp.BodySize
	result.ResponseHash = resp.BodySHA256
	result.Duration = resp.Duration
	result.TLSMetadata = resp.TLSMetadata
	result.RedirectChain = resp.RedirectChain
	result.Headers = sanitizeHeaders(resp.Headers)
	result.CookieNames = extractCookieNames(resp.Headers)
	result.Cookies = extractCookieAttributes(resp.Headers)

	if isRedirectStatus(resp.StatusCode) {
		location := resp.Headers.Get("Location")
		if location != "" && scope != nil && !scope.AllowedURL(resolveLocation(resp.URL, location)) {
			result.RedirectBlocked = true
			result.Skipped = true
			result.SkippedReason = "out-of-scope redirect encountered and not followed: " + location
			result.Indicators = append(result.Indicators, "redirect to out-of-scope location was not followed: "+location)
			result.ServiceType = model.ServiceUnknown
			return result
		}
	}

	path := candidatePath(c.URL)
	analysis := Analyze(path, resp)
	result.ServiceType = analysis.ServiceType
	result.Indicators = append(result.Indicators, analysis.Indicators...)

	if cfg.DetectAIEndpoints {
		ai := ClassifyAICandidate(path, analysis.IsJSON, analysis.JSONBody)
		result.AIEndpointCandidate = ai.Candidate
		result.Confidence = ai.Confidence
		result.Indicators = append(result.Indicators, ai.Evidence...)
		if ai.Candidate {
			result.ServiceType = model.ServiceAICandidate
		}
	}

	return result
}

// sanitizeHeaders redacts sensitive header values (Authorization, Cookie,
// Set-Cookie, API keys, ...) using the same redaction boundary Phase 2
// applies to asset/evidence metadata — see
// internal/domain/asset.SanitizeMetadata — rather than a second,
// discovery-specific redaction implementation (phase3.md §22/§3).
func sanitizeHeaders(h http.Header) map[string][]string {
	raw := make(map[string]any, len(h))
	for k, v := range h {
		values := make([]any, len(v))
		for i, s := range v {
			values[i] = s
		}
		raw[k] = values
	}

	sanitized := domainasset.SanitizeMetadata(raw)

	out := make(map[string][]string, len(sanitized))
	for k, v := range sanitized {
		switch val := v.(type) {
		case []any:
			strs := make([]string, len(val))
			for i, item := range val {
				if s, ok := item.(string); ok {
					strs[i] = s
				} else {
					strs[i] = fmt.Sprintf("%v", item)
				}
			}
			out[k] = strs
		case string:
			// A sensitive key's entire value is replaced with the single
			// string "[REDACTED]" by SanitizeMetadata.
			out[k] = []string{val}
		}
	}
	return out
}

// extractCookieNames returns every distinct cookie name set via
// Set-Cookie — never a value (phase6.md §13/§31). It must run against h,
// the raw pre-redaction header set — sanitizeHeaders (above) replaces
// Set-Cookie's entire value with "[REDACTED]", which would make name
// extraction impossible if this ran afterward.
func extractCookieNames(h http.Header) []string {
	raw := h["Set-Cookie"]
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(raw))
	var names []string
	for _, line := range raw {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name == "" || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		names = append(names, c.Name)
	}
	return names
}

// extractCookieAttributes returns each Set-Cookie's name plus its
// Secure/HttpOnly/SameSite attributes — never a value (phase8.md §22/§23).
// It must run against h, the raw pre-redaction header set, for the same
// reason extractCookieNames does.
func extractCookieAttributes(h http.Header) []model.CookieAttribute {
	raw := h["Set-Cookie"]
	if len(raw) == 0 {
		return nil
	}
	var cookies []model.CookieAttribute
	for _, line := range raw {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name == "" {
			continue
		}
		sameSite := ""
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		cookies = append(cookies, model.CookieAttribute{
			Name: c.Name, Secure: c.Secure, HTTPOnly: c.HttpOnly, SameSite: sameSite,
		})
	}
	return cookies
}

func isRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// resolveLocation resolves a (possibly relative) Location header value
// against the URL of the response that carried it.
func resolveLocation(baseURL, location string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return location
	}
	loc, err := url.Parse(location)
	if err != nil {
		return location
	}
	return base.ResolveReference(loc).String()
}

// candidatePath extracts just the path component of a (already-normalized)
// candidate URL, for path-based classification/indicator lookups.
func candidatePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}
