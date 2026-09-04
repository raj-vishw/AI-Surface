package service

import (
	"testing"
	"time"

	discoverynet "ai-recon-platform/internal/discovery/network"
)

func TestBuildNetworkMetadata_CertificateNotAfter(t *testing.T) {
	notAfter := time.Date(2030, 1, 15, 0, 0, 0, 0, time.UTC)
	result := discoverynet.PortResult{
		TLSMetadata: &discoverynet.TLSMetadata{
			Version: "TLS 1.3", Subject: "example.com", Issuer: "Let's Encrypt", NotAfter: notAfter,
		},
	}

	metadata := buildNetworkMetadata(result, true)

	got, ok := metadata["certificate_not_after"].(string)
	if !ok {
		t.Fatalf("expected certificate_not_after to be a string, got %#v", metadata["certificate_not_after"])
	}
	if got != notAfter.Format(time.RFC3339) {
		t.Errorf("certificate_not_after = %q, want %q", got, notAfter.Format(time.RFC3339))
	}
}

func TestBuildNetworkMetadata_NoCertificateNotAfterWhenZero(t *testing.T) {
	result := discoverynet.PortResult{
		TLSMetadata: &discoverynet.TLSMetadata{Version: "TLS 1.2"},
	}
	metadata := buildNetworkMetadata(result, true)
	if _, ok := metadata["certificate_not_after"]; ok {
		t.Errorf("expected no certificate_not_after when NotAfter is zero, got %#v", metadata["certificate_not_after"])
	}
}
