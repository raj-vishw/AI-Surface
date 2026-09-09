package detectors

import (
	"context"
	"strings"

	"ai-surface-platform/internal/detection"
)

// cookieDetector flags a Set-Cookie observed without Secure and/or
// HttpOnly, or with SameSite=None while not Secure (phase8.md §22).
// Cookie *values* are never available to this detector — only the
// name/attribute shape internal/discovery/http's extractCookieAttributes
// captured (phase8.md §23) — so it can never accidentally leak or reason
// about session content.
type cookieDetector struct{}

func (cookieDetector) ID() string   { return "cookies.insecure-cookie" }
func (cookieDetector) Name() string { return "Insecure Cookie Configuration" }
func (cookieDetector) Description() string {
	return "Detects cookies observed without Secure/HttpOnly, or SameSite=None without Secure."
}
func (cookieDetector) Version() int                 { return 1 }
func (cookieDetector) Category() detection.Category { return detection.CategoryConfiguration }
func (cookieDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d cookieDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !httpAnalyzed(ep) {
			continue
		}
		https := isHTTPS(ep.URL)
		for _, c := range cookiesFromMetadata(ep.Metadata) {
			problems := cookieProblems(c, https)
			if len(problems) == 0 {
				continue
			}
			id := ep.ID
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID() + "." + strings.ToLower(c.Name), DetectorVersion: d.Version(),
				Title:       "Insecure cookie configuration: " + c.Name,
				Description: "The cookie \"" + c.Name + "\" was observed with the following weaknesses: " + strings.Join(problems, ", ") + ".",
				Category:    detection.CategoryConfiguration, Scope: detection.ScopeEndpoint,
				Severity: cookieSeverity(problems), Confidence: 0.9,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceCookieMetadata, map[string]any{
					"url": endpointLabel(ep), "name": c.Name, "secure": c.Secure, "httponly": c.HTTPOnly,
					"samesite": c.SameSite, "problems": problems,
				}, 0.9)},
				Remediation: "Set Secure and HttpOnly on every session/auth cookie, and never combine SameSite=None with a missing Secure attribute.",
				References:  []detection.Reference{detection.ReferenceMDNSetCookie, detection.ReferenceOWASPSecurityMisconfiguration},
			})
		}
	}
	return findings, nil
}

// cookieProblems lists which of Secure/HttpOnly/SameSite are misconfigured
// for c, given whether the endpoint that set it was HTTPS. Detection here
// deliberately flags every cookie's attribute shape, not just ones whose
// name looks like a session identifier — phase8.md §22's worked example
// ("session cookie") is illustrative, not a name-matching requirement, and
// guessing which cookies are "important" from their name risks both false
// negatives (a differently-named session cookie) and an implication this
// detector inspects cookie content it never sees.
func cookieProblems(c cookieAttribute, https bool) []string {
	var problems []string
	if https && !c.Secure {
		problems = append(problems, "missing Secure")
	}
	if !c.HTTPOnly {
		problems = append(problems, "missing HttpOnly")
	}
	if strings.EqualFold(c.SameSite, "None") && !c.Secure {
		problems = append(problems, "SameSite=None without Secure")
	}
	return problems
}

func cookieSeverity(problems []string) detection.Severity {
	for _, p := range problems {
		if strings.Contains(p, "SameSite=None") {
			return detection.SeverityMedium
		}
	}
	if len(problems) >= 2 {
		return detection.SeverityMedium
	}
	return detection.SeverityLow
}
