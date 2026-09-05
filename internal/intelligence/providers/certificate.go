package providers

import (
	"context"
	"strings"
	"time"

	"ai-recon-platform/internal/intelligence"
)

const certificateProviderVersion = "1"

// CertificateProvider surfaces already-persisted TLS certificate metadata
// (Phase 4/8) for a host/certificate indicator (phase10.md §9). It never
// exposes private-key material — CertificateObservation carries only
// public certificate fields (phase10.md §9).
type CertificateProvider struct {
	source *DatasetSource
}

// NewCertificateProvider builds a CertificateProvider reading from source.
func NewCertificateProvider(source *DatasetSource) *CertificateProvider {
	return &CertificateProvider{source: source}
}

// ID implements intelligence.Provider.
func (p *CertificateProvider) ID() string { return "certificate" }

// Name implements intelligence.Provider.
func (p *CertificateProvider) Name() string { return "Certificate Enrichment" }

// Version implements intelligence.Provider.
func (p *CertificateProvider) Version() string { return certificateProviderVersion }

// Capabilities implements intelligence.Provider.
func (p *CertificateProvider) Capabilities() []intelligence.Capability {
	return []intelligence.Capability{intelligence.CapabilityCertificate}
}

// Lookup implements intelligence.Provider.
func (p *CertificateProvider) Lookup(_ context.Context, indicator intelligence.Indicator) ([]intelligence.Record, error) {
	cert, ok := p.source.Get().Certificates[indicator.Value]
	if !ok {
		return nil, nil
	}

	var expiration *time.Time
	if !cert.NotAfter.IsZero() {
		t := cert.NotAfter
		expiration = &t
	}

	return []intelligence.Record{{
		Indicator: indicator, SourceType: "certificate",
		Verdict: intelligence.VerdictUnknown, Confidence: intelligence.ConfidenceHigh,
		Expiration: expiration, RetrievedAt: time.Now().UTC(),
		SourceReference: cert.SerialNumber,
		NormalizedData: map[string]any{
			"issuer":               cert.Issuer,
			"subject":              cert.Subject,
			"sans":                 cert.SANs,
			"not_after":            cert.NotAfter,
			"serial_number":        cert.SerialNumber,
			"signature_algorithm":  cert.SignatureAlgorithm,
			"public_key_algorithm": cert.PublicKeyAlgorithm,
		},
	}}, nil
}

// RelatedHostnames returns the hostnames in cert.SANs that are NOT
// indicator.Value itself — candidate related assets sharing this
// certificate (phase10.md §10's "*.example.com may relate api.example.com
// / admin.example.com" example). This is evidence a relationship MAY
// exist, never a claim of common ownership on its own (phase10.md §10 —
// "do not claim ownership solely from certificate similarity"); the
// caller is responsible for only creating a relationship when the
// candidate hostname is also independently known to this platform (an
// existing asset), exactly the same "only create relationships when
// evidence supports them" discipline phase9.md's correlation rules use.
func RelatedHostnames(cert CertificateObservation, indicatorValue string) []string {
	var out []string
	seen := map[string]bool{strings.ToLower(indicatorValue): true}
	for _, san := range cert.SANs {
		san = strings.ToLower(strings.TrimSpace(san))
		if san == "" || seen[san] || strings.HasPrefix(san, "*.") {
			continue
		}
		seen[san] = true
		out = append(out, san)
	}
	return out
}
