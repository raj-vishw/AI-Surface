package detection

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
	domainasset "ai-recon-platform/internal/domain/asset"
	domainfinding "ai-recon-platform/internal/domain/finding"
)

func TestToDomainFinding_ComputesIdentityKeyAndDefaults(t *testing.T) {
	targetID, assetID, scanID := uuid.New(), uuid.New(), uuid.New()
	f := detection.Finding{
		AssetID: assetID, DetectorID: "d.id", Title: "T", Category: detection.CategorySecurityHeaders,
		Scope: detection.ScopeAsset, Severity: detection.SeverityMedium, Confidence: 0.7,
	}

	got := toDomainFinding(f, targetID, scanID)

	wantKey := domainfinding.IdentityKey(targetID, assetID, nil, "d.id")
	if got.IdentityKey != wantKey {
		t.Errorf("IdentityKey = %q, want %q", got.IdentityKey, wantKey)
	}
	if got.Status != domainfinding.StatusOpen {
		t.Errorf("expected default status open, got %q", got.Status)
	}
	if got.Severity != domainfinding.SeverityMedium || got.DetectorSeverity != domainfinding.SeverityMedium {
		t.Errorf("expected severity/detector_severity both medium, got %q/%q", got.Severity, got.DetectorSeverity)
	}
	if got.ScanID == nil || *got.ScanID != scanID {
		t.Errorf("expected ScanID set to %v, got %v", scanID, got.ScanID)
	}
}

func TestToDomainFinding_SanitizesMetadata(t *testing.T) {
	targetID, assetID := uuid.New(), uuid.New()
	f := detection.Finding{
		AssetID: assetID, DetectorID: "d", Title: "T", Category: detection.CategoryConfiguration, Scope: detection.ScopeAsset,
		Severity: detection.SeverityLow, Metadata: map[string]any{"authorization": "Bearer secret-token"},
	}
	got := toDomainFinding(f, targetID, uuid.New())
	if got.Metadata["authorization"] != "[REDACTED]" {
		t.Errorf("expected sensitive metadata redacted, got %#v", got.Metadata)
	}
}

func TestConvertServiceObservations(t *testing.T) {
	host := "example.test"
	port := 5432
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	assets := []domainasset.Asset{
		{
			Hostname: &host, Port: &port,
			Metadata: map[string]any{
				"state": "OPEN", "service": "DATABASE", "protocol": "tcp",
				"tls_version": "TLS 1.2", "tls_cipher_suite": "TLS_AES_128_GCM_SHA256",
				"certificate_subject": "example.test", "certificate_issuer": "Let's Encrypt",
				"certificate_not_after": notAfter,
			},
		},
	}

	tls, services := convertServiceObservations(assets)
	if len(services) != 1 || services[0].Port != 5432 || services[0].State != "OPEN" {
		t.Fatalf("unexpected services: %#v", services)
	}
	if len(tls) != 1 || tls[0].Version != "TLS 1.2" || tls[0].NotAfter.IsZero() {
		t.Fatalf("unexpected tls observations: %#v", tls)
	}
}

func TestConvertServiceObservations_NoTLSWhenVersionAbsent(t *testing.T) {
	host := "example.test"
	assets := []domainasset.Asset{{Hostname: &host, Metadata: map[string]any{"state": "OPEN", "service": "HTTP"}}}
	tls, services := convertServiceObservations(assets)
	if len(tls) != 0 {
		t.Fatalf("expected no TLS observation without tls_version, got %#v", tls)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service observation, got %d", len(services))
	}
}

func TestChangeTypeForEvent(t *testing.T) {
	cases := map[domainfinding.EventType]detection.ChangeType{
		domainfinding.EventOpened:   detection.ChangeNew,
		domainfinding.EventReopened: detection.ChangeReopened,
		domainfinding.EventResolved: detection.ChangeResolved,
		domainfinding.EventUpdated:  "",
	}
	for in, want := range cases {
		if got := changeTypeForEvent(in); got != want {
			t.Errorf("changeTypeForEvent(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestEventTypeFor(t *testing.T) {
	cases := map[detection.ChangeType]domainfinding.EventType{
		detection.ChangeNew:        domainfinding.EventOpened,
		detection.ChangeReopened:   domainfinding.EventReopened,
		detection.ChangeResolved:   domainfinding.EventResolved,
		detection.ChangePersisting: domainfinding.EventUpdated,
	}
	for in, want := range cases {
		if got := eventTypeFor(in); got != want {
			t.Errorf("eventTypeFor(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestAssetOrigin_PrefersURL(t *testing.T) {
	url := "https://example.test:8443/"
	scheme, host, port := assetOrigin(domainasset.Asset{URL: &url})
	if scheme != "https" || host != "example.test" || port != 8443 {
		t.Errorf("unexpected origin: %s %s %d", scheme, host, port)
	}
}

func TestAssetOrigin_FallsBackToFields(t *testing.T) {
	protocol, hostname := "https", "example.test"
	scheme, host, port := assetOrigin(domainasset.Asset{Protocol: &protocol, Hostname: &hostname})
	if scheme != "https" || host != "example.test" || port != 443 {
		t.Errorf("unexpected origin: %s %s %d", scheme, host, port)
	}
}

func TestMapEvidenceType_FallsBackForUnrecognized(t *testing.T) {
	if got := mapEvidenceType("not_a_real_type"); got != domainfinding.EvidenceConfiguration {
		t.Errorf("expected fallback to EvidenceConfiguration, got %q", got)
	}
	if got := mapEvidenceType(detection.EvidenceHTTPHeader); got != domainfinding.EvidenceHTTPHeader {
		t.Errorf("expected passthrough for a recognized type, got %q", got)
	}
}
