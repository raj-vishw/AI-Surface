package detectors

import (
	"context"
	"time"

	"ai-recon-platform/internal/detection"
)

// obsoleteTLSVersions are protocol versions considered obsolete
// configuration (phase8.md §24's "obsolete protocol configuration") —
// TLS 1.0/1.1 are deprecated by RFC 8996 and disabled by default in
// current browsers/clients.
var obsoleteTLSVersions = map[string]bool{"TLS 1.0": true, "TLS 1.1": true}

// certificateExpirationDetector flags a certificate that is already
// expired (critical — the connection is actively broken for validating
// clients) or expiring within Config.CertificateExpiryWarnDays
// (informational — a heads-up, not equivalent to a compromised
// certificate; phase8.md §25). It relies entirely on Phase 4's
// already-persisted TLS probe (see internal/discovery/network's
// probeTLS and this project's certificate_not_after metadata extension)
// — it never opens a TLS connection of its own.
type certificateExpirationDetector struct{ now func() time.Time }

func (d certificateExpirationDetector) ID() string { return "tls.certificate-expiration" }
func (certificateExpirationDetector) Name() string { return "Certificate Expiration" }
func (certificateExpirationDetector) Description() string {
	return "Detects an already-expired certificate, or one expiring within the configured threshold."
}
func (certificateExpirationDetector) Version() int { return 1 }
func (certificateExpirationDetector) Category() detection.Category {
	return detection.CategoryCertificate
}
func (certificateExpirationDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d certificateExpirationDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	nowFn := d.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC()
	warnWithin := time.Duration(input.Config.ExpiryWarnDays()) * 24 * time.Hour

	var findings []detection.Finding
	for _, obs := range input.TLS {
		if obs.NotAfter.IsZero() {
			continue
		}
		remaining := obs.NotAfter.Sub(now)

		switch {
		case remaining <= 0:
			findings = append(findings, expirationFinding(d, input, obs, detection.SeverityCritical,
				"Expired TLS certificate",
				"The certificate observed for this host expired on "+obs.NotAfter.Format(time.RFC3339)+" and is no longer valid for validating clients.", 0.95))
		case remaining <= warnWithin:
			findings = append(findings, expirationFinding(d, input, obs, detection.SeverityInformational,
				"TLS certificate expiring soon",
				"The certificate observed for this host expires on "+obs.NotAfter.Format(time.RFC3339)+", within the configured warning threshold.", 0.9))
		}
	}
	return findings, nil
}

func expirationFinding(d certificateExpirationDetector, input detection.Input, obs detection.TLSObservation, severity detection.Severity, title, description string, confidence detection.Confidence) detection.Finding {
	return detection.Finding{
		AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
		Title: title, Description: description,
		Category: detection.CategoryCertificate, Scope: detection.ScopeAsset,
		Severity: severity, Confidence: confidence,
		Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceTLSMetadata, map[string]any{
			"host": obs.Host, "port": obs.Port, "subject": obs.Subject, "issuer": obs.Issuer,
			"not_after": obs.NotAfter.Format(time.RFC3339),
		}, confidence)},
		Remediation: "Renew the certificate before expiration and confirm automated renewal is configured to prevent recurrence.",
	}
}

// obsoleteProtocolDetector flags a TLS handshake that negotiated TLS
// 1.0/1.1 (phase8.md §24). It reports only the version Phase 4 actually
// observed being negotiated — never a claim about which versions the
// server *supports*, since a single handshake only reveals what was
// negotiated that one time.
type obsoleteProtocolDetector struct{}

func (obsoleteProtocolDetector) ID() string   { return "tls.obsolete-protocol" }
func (obsoleteProtocolDetector) Name() string { return "Obsolete TLS Protocol" }
func (obsoleteProtocolDetector) Description() string {
	return "Detects a TLS handshake that negotiated TLS 1.0 or 1.1."
}
func (obsoleteProtocolDetector) Version() int                 { return 1 }
func (obsoleteProtocolDetector) Category() detection.Category { return detection.CategoryCryptography }
func (obsoleteProtocolDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d obsoleteProtocolDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, obs := range input.TLS {
		if !obsoleteTLSVersions[obs.Version] {
			continue
		}
		findings = append(findings, detection.Finding{
			AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Obsolete TLS protocol negotiated",
			Description: "A TLS handshake against this host negotiated " + obs.Version + ", a deprecated protocol version (RFC 8996) that current browsers and clients disable by default.",
			Category:    detection.CategoryCryptography, Scope: detection.ScopeAsset,
			Severity: detection.SeverityMedium, Confidence: 0.9,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceTLSMetadata, map[string]any{
				"host": obs.Host, "port": obs.Port, "version": obs.Version, "cipher_suite": obs.CipherSuite,
			}, 0.9)},
			Remediation: "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
			References:  []detection.Reference{detection.ReferenceOWASPCryptographicFailures},
		})
	}
	return findings, nil
}
