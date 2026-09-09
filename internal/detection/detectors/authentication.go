package detectors

import (
	"context"

	"ai-surface-platform/internal/detection"
)

// authSurfaceDetector reports an endpoint Phase 7's classifier already
// identified as auth-shaped (login, password reset, OAuth, ...) as an
// informational inventory finding (phase8.md §37). It is deliberately
// inventory-only: no credential is ever attempted, no bypass is ever
// tested, and no brute-force of any kind occurs — the finding exists so a
// reviewer knows where the authentication surface is, nothing more.
type authSurfaceDetector struct{}

func (authSurfaceDetector) ID() string   { return "authentication.surface-inventory" }
func (authSurfaceDetector) Name() string { return "Authentication Surface Discovered" }
func (authSurfaceDetector) Description() string {
	return "Reports an endpoint classified as an authentication surface (login/password-reset/OAuth) as inventory."
}
func (authSurfaceDetector) Version() int                 { return 1 }
func (authSurfaceDetector) Category() detection.Category { return detection.CategoryAuthentication }
func (authSurfaceDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d authSurfaceDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if ep.Classification != "auth" || !ep.Observed {
			continue
		}
		httpsOK := isHTTPS(ep.URL)
		severity := detection.SeverityInformational
		description := "An authentication-related endpoint (login, password reset, or OAuth flow) was observed at this path. This is an inventory observation only."
		if !httpsOK {
			severity = detection.SeverityMedium
			description += " It was observed over plain HTTP, meaning any credential this endpoint accepts would traverse the network unencrypted."
		}

		id := ep.ID
		evidence := map[string]any{"url": endpointLabel(ep), "classification": "auth", "https": httpsOK}
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Authentication surface discovered",
			Description: description,
			Category:    detection.CategoryAuthentication, Scope: detection.ScopeEndpoint,
			Severity: severity, Confidence: 0.6,
			Evidence:    []detection.Evidence{detection.NewEvidence(detection.EvidenceClassification, evidence, 0.6)},
			Remediation: "Confirm this endpoint enforces HTTPS, rate limiting, and account lockout/anti-automation controls appropriate to an authentication surface.",
			References:  []detection.Reference{detection.ReferenceOWASPIdentificationAuthFailures},
		})
	}
	return findings, nil
}
