// Package detectors implements Phase 8's built-in Detector set (phase8.md
// §16-§41) and RegisterAll, which registers every one of them into an
// internal/detection.Registry. Each detector's own file documents its
// positive/negative signals and severity rationale inline (phase8.md
// §57), rather than routing through a central opaque rules engine.
package detectors

import (
	"net/url"
	"strconv"
	"strings"

	"ai-recon-platform/internal/detection"
)

// headerFromMetadata reads one curated response header from an asset's or
// endpoint's already-persisted, already-sanitized Metadata map — see
// internal/discovery/service/discovery.go's safeHeaderSubset, which is
// the only place "headers" is ever populated, and only for the names in
// fingerprintHeaderAllowlist/detectionHeaderAllowlist. A header this
// project never captures — or one this endpoint's Metadata simply lacks
// (e.g. a Phase 7 crawl result that never ran a full Phase 3 HTTP
// analysis) — returns "": absence of evidence, never a manufactured
// finding.
func headerFromMetadata(metadata map[string]any, name string) string {
	headers, ok := metadata["headers"].(map[string]any)
	if !ok {
		return ""
	}
	v, ok := headers[name]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func stringFromMetadata(metadata map[string]any, key string) string {
	v, ok := metadata[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// cookieAttribute is the decoded form of one "cookie_attributes" entry
// (see internal/discovery/service/discovery.go) — name plus
// Secure/HttpOnly/SameSite only, never a value.
type cookieAttribute struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

func cookiesFromMetadata(metadata map[string]any) []cookieAttribute {
	raw, ok := metadata["cookie_attributes"].([]any)
	if !ok {
		return nil
	}
	out := make([]cookieAttribute, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		secure, _ := m["secure"].(bool)
		httpOnly, _ := m["httponly"].(bool)
		sameSite, _ := m["samesite"].(string)
		out = append(out, cookieAttribute{Name: name, Secure: secure, HTTPOnly: httpOnly, SameSite: sameSite})
	}
	return out
}

// isHTTPS reports whether rawURL uses the https scheme.
func isHTTPS(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}

// looksLikeHTMLResponse reports whether contentType/classification
// indicates a browser-rendered page — the kind of response security
// headers like CSP/X-Frame-Options meaningfully apply to, as opposed to a
// JSON API response or a static asset (phase8.md §16: "the detector must
// account for... endpoint type, static resources, API responses").
func looksLikeHTMLResponse(contentType string, classification string) bool {
	if classification == "static" || classification == "asset" {
		return false
	}
	ct := strings.ToLower(contentType)
	if ct == "" {
		// Unknown content-type: only trust a non-API/non-static
		// classification, never assume HTML from silence.
		return classification == "page" || classification == "documentation"
	}
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// endpointLabel returns a human-readable identifier for an endpoint,
// preferring its URL.
func endpointLabel(ep detection.EndpointObservation) string {
	if ep.URL != "" {
		return ep.URL
	}
	return ep.Path
}

// baseOrigin returns "scheme://host[:port]" for asset — the fixed base a
// safe-active detector may request one of its own small, hardcoded
// well-known paths against (never a caller-supplied or discovered path
// outside that fixed set — phase8.md §15/§29).
func baseOrigin(asset detection.AssetObservation) string {
	if asset.Scheme == "" || asset.Host == "" {
		return ""
	}
	origin := asset.Scheme + "://" + asset.Host
	if asset.Port != 0 && !isDefaultPort(asset.Scheme, asset.Port) {
		origin += ":" + strconv.Itoa(asset.Port)
	}
	return origin
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}

// safeActiveReady reports whether input is configured to allow a
// safe-active detector to actually issue a request.
func safeActiveReady(input detection.Input) bool {
	return input.Mode == detection.ModeSafeActive && input.Fetcher != nil && baseOrigin(input.Asset) != ""
}

// maxResponseBytes returns cfg's effective MaxResponseSize as an int,
// bounded to detection.DefaultMaxResponseSize when unset — SafeActiveFetcher.
// Fetch takes an int, while Config.MaxResponseSize is int64 to mirror
// every other discovery engine's response-size configuration in this
// project.
func maxResponseBytes(cfg detection.Config) int {
	if cfg.MaxResponseSize <= 0 {
		return int(detection.DefaultMaxResponseSize)
	}
	return int(cfg.MaxResponseSize)
}
