package detectors

import (
	"context"
	"strings"

	"ai-recon-platform/internal/detection"
)

// httpAnalyzed reports whether ep carries evidence Phase 3's full HTTP
// discovery actually inspected this response's headers (discovery_method
// == "http" — see internal/discovery/service/discovery.go's buildMetadata,
// which unconditionally attempts header capture, unlike Phase 7's
// lighter-weight crawl metadata). Every security-header/cookie/CORS
// detector gates on this first: an endpoint discovered only by Phase 7's
// crawler (no header capture at all) must never be reported as "missing"
// a header this project never actually looked for — that would be a
// false positive from absence of evidence, not evidence of absence
// (phase8.md §57).
func httpAnalyzed(ep detection.EndpointObservation) bool {
	return stringFromMetadata(ep.Metadata, "discovery_method") == "http"
}

// applicableForHeaders reports whether ep is the kind of response
// security headers meaningfully apply to: a rendered page, not a static
// asset or a non-2xx/3xx error response with nothing to protect
// (phase8.md §16).
func applicableForHeaders(ep detection.EndpointObservation) bool {
	if !httpAnalyzed(ep) {
		return false
	}
	if ep.StatusCode == 0 || ep.StatusCode >= 400 {
		return false
	}
	return looksLikeHTMLResponse(ep.ContentType, ep.Classification)
}

// --- HSTS ---------------------------------------------------------------

// hstsDetector flags an HTTPS response with no Strict-Transport-Security
// header (phase8.md §17). It never fires for plain HTTP endpoints — HSTS
// is meaningless there, and reporting it would misstate what was observed.
type hstsDetector struct{}

func (hstsDetector) ID() string   { return "security_headers.missing-hsts" }
func (hstsDetector) Name() string { return "Missing HSTS" }
func (hstsDetector) Description() string {
	return "Detects HTTPS responses that never send Strict-Transport-Security."
}
func (hstsDetector) Version() int                 { return 1 }
func (hstsDetector) Category() detection.Category { return detection.CategorySecurityHeaders }
func (hstsDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d hstsDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !applicableForHeaders(ep) || !isHTTPS(ep.URL) {
			continue
		}
		if headerFromMetadata(ep.Metadata, "Strict-Transport-Security") != "" {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Missing HSTS",
			Description: "This HTTPS endpoint was observed without a Strict-Transport-Security response header, so browsers are not instructed to prefer HTTPS for future requests to this host.",
			Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityLow, Confidence: 0.9,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
				"url": endpointLabel(ep), "header": "Strict-Transport-Security", "observed": false,
			}, 0.9)},
			Remediation: "Send Strict-Transport-Security on every HTTPS response, with an appropriate max-age, and consider includeSubDomains once every subdomain is confirmed to serve HTTPS.",
			References:  []detection.Reference{detection.ReferenceMDNHSTS, detection.ReferenceRFC6797},
		})
	}
	return findings, nil
}

// --- Content-Security-Policy ---------------------------------------------

// weakCSPFragments are directive fragments that clearly undermine CSP's
// purpose when present — deliberately narrow (phase8.md §18: "avoid
// simplistic checks such as contains('*') being automatically critical").
// A bare "*" as a source is common and often intentional for
// non-script/style directives, so it alone is never flagged; only
// unsafe-inline/unsafe-eval on script-src, or a wildcard specifically on
// script-src/object-src, are treated as "weak".
var weakCSPPatterns = []string{"script-src *", "script-src * ", "object-src *"}

// cspDetector flags a response with no Content-Security-Policy, or one
// whose script-src/object-src directives are configured in a way that is
// unambiguously weak (phase8.md §18).
type cspDetector struct{}

func (cspDetector) ID() string   { return "security_headers.csp" }
func (cspDetector) Name() string { return "Content-Security-Policy" }
func (cspDetector) Description() string {
	return "Detects a missing or clearly weak Content-Security-Policy on rendered pages."
}
func (cspDetector) Version() int                 { return 1 }
func (cspDetector) Category() detection.Category { return detection.CategorySecurityHeaders }
func (cspDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d cspDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !applicableForHeaders(ep) {
			continue
		}
		csp := headerFromMetadata(ep.Metadata, "Content-Security-Policy")
		id := ep.ID

		switch {
		case csp == "":
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
				Title:       "Missing Content-Security-Policy",
				Description: "This page was observed without a Content-Security-Policy response header, so the browser applies no restriction on script/resource sources beyond the same-origin default.",
				Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
				Severity: detection.SeverityMedium, Confidence: 0.9,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
					"url": endpointLabel(ep), "header": "Content-Security-Policy", "observed": false, "classification": "missing",
				}, 0.9)},
				Remediation: "Configure an appropriate Content-Security-Policy that restricts script, style, and object sources to trusted origins.",
				References:  []detection.Reference{detection.ReferenceMDNCSP, detection.ReferenceOWASPSecurityMisconfiguration},
			})
		case cspLooksWeak(csp):
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
				Title:       "Weak Content-Security-Policy",
				Description: "This page's Content-Security-Policy allows unsafe-inline/unsafe-eval script execution or an unrestricted script/object source, both of which substantially reduce CSP's ability to mitigate injected script content.",
				Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
				Severity: detection.SeverityLow, Confidence: 0.7,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
					"url": endpointLabel(ep), "header": "Content-Security-Policy", "observed": true, "classification": "weak", "value_excerpt": detection.TruncateExcerpt(csp, 200),
				}, 0.7)},
				Remediation: "Avoid 'unsafe-inline'/'unsafe-eval' in script-src, and avoid wildcard sources on script-src/object-src; use nonces or hashes for inline scripts instead.",
				References:  []detection.Reference{detection.ReferenceMDNCSP},
			})
		}
	}
	return findings, nil
}

func cspLooksWeak(csp string) bool {
	lower := strings.ToLower(csp)
	if strings.Contains(lower, "script-src") && (strings.Contains(lower, "unsafe-inline") || strings.Contains(lower, "unsafe-eval")) {
		return true
	}
	for _, pattern := range weakCSPPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// --- X-Content-Type-Options ----------------------------------------------

type xContentTypeOptionsDetector struct{}

func (xContentTypeOptionsDetector) ID() string {
	return "security_headers.missing-x-content-type-options"
}
func (xContentTypeOptionsDetector) Name() string { return "Missing X-Content-Type-Options" }
func (xContentTypeOptionsDetector) Description() string {
	return "Detects responses missing X-Content-Type-Options: nosniff."
}
func (xContentTypeOptionsDetector) Version() int { return 1 }
func (xContentTypeOptionsDetector) Category() detection.Category {
	return detection.CategorySecurityHeaders
}
func (xContentTypeOptionsDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d xContentTypeOptionsDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !applicableForHeaders(ep) {
			continue
		}
		v := headerFromMetadata(ep.Metadata, "X-Content-Type-Options")
		if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Missing X-Content-Type-Options",
			Description: "This response was observed without X-Content-Type-Options: nosniff, so browsers may MIME-sniff the response body and render it as a different content type than declared.",
			Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityLow, Confidence: 0.85,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
				"url": endpointLabel(ep), "header": "X-Content-Type-Options", "observed": v != "", "value": v,
			}, 0.85)},
			Remediation: "Send X-Content-Type-Options: nosniff on every response.",
			References:  []detection.Reference{detection.ReferenceOWASPSecurityMisconfiguration},
		})
	}
	return findings, nil
}

// --- Referrer-Policy -------------------------------------------------------

// weakReferrerPolicies are the values phase8.md §20 calls out as
// non-ideal but not automatically a vulnerability — kept as a distinct,
// lower-severity classification from "missing entirely" rather than being
// treated identically to it.
var weakReferrerPolicies = map[string]bool{
	"unsafe-url": true, "no-referrer-when-downgrade": true,
}

type referrerPolicyDetector struct{}

func (referrerPolicyDetector) ID() string   { return "security_headers.referrer-policy" }
func (referrerPolicyDetector) Name() string { return "Referrer-Policy" }
func (referrerPolicyDetector) Description() string {
	return "Detects a missing or overly permissive Referrer-Policy."
}
func (referrerPolicyDetector) Version() int                 { return 1 }
func (referrerPolicyDetector) Category() detection.Category { return detection.CategorySecurityHeaders }
func (referrerPolicyDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d referrerPolicyDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !applicableForHeaders(ep) {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(headerFromMetadata(ep.Metadata, "Referrer-Policy")))
		id := ep.ID

		switch {
		case v == "":
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
				Title:       "Missing Referrer-Policy",
				Description: "This page was observed without a Referrer-Policy header, so the browser's default (origin-when-cross-origin in most current browsers) governs how much of this page's URL is sent to destinations it links to.",
				Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
				Severity: detection.SeverityInformational, Confidence: 0.8,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
					"url": endpointLabel(ep), "header": "Referrer-Policy", "observed": false,
				}, 0.8)},
				Remediation: "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin.",
			})
		case weakReferrerPolicies[v]:
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
				Title:       "Permissive Referrer-Policy",
				Description: "This page's Referrer-Policy (" + v + ") sends the full referrer URL, including any sensitive path/query data, to cross-origin destinations.",
				Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
				Severity: detection.SeverityInformational, Confidence: 0.7,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
					"url": endpointLabel(ep), "header": "Referrer-Policy", "observed": true, "value": v,
				}, 0.7)},
				Remediation: "Prefer strict-origin-when-cross-origin or no-referrer over " + v + ".",
			})
		}
	}
	return findings, nil
}

// --- Permissions-Policy ----------------------------------------------------

type permissionsPolicyDetector struct{}

func (permissionsPolicyDetector) ID() string   { return "security_headers.missing-permissions-policy" }
func (permissionsPolicyDetector) Name() string { return "Missing Permissions-Policy" }
func (permissionsPolicyDetector) Description() string {
	return "Detects a page with no Permissions-Policy declared."
}
func (permissionsPolicyDetector) Version() int { return 1 }
func (permissionsPolicyDetector) Category() detection.Category {
	return detection.CategorySecurityHeaders
}
func (permissionsPolicyDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d permissionsPolicyDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !applicableForHeaders(ep) {
			continue
		}
		if headerFromMetadata(ep.Metadata, "Permissions-Policy") != "" {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Missing Permissions-Policy",
			Description: "This page was observed without a Permissions-Policy header, so it does not explicitly restrict which browser features (camera, microphone, geolocation, ...) it or any embedded frame may use.",
			Category:    detection.CategorySecurityHeaders, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityInformational, Confidence: 0.8,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
				"url": endpointLabel(ep), "header": "Permissions-Policy", "observed": false,
			}, 0.8)},
			Remediation: "Declare a Permissions-Policy that restricts powerful browser features to the origins that actually need them.",
		})
	}
	return findings, nil
}
