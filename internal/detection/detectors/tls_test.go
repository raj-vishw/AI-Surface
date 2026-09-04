package detectors

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func TestCertificateExpirationDetector_Expired(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := certificateExpirationDetector{now: func() time.Time { return fixedNow }}

	input := detection.Input{
		Asset:  detection.AssetObservation{ID: uuid.New()},
		TLS:    []detection.TLSObservation{{Host: "example.test", Port: 443, NotAfter: fixedNow.AddDate(0, 0, -1)}},
		Config: detection.Config{CertificateExpiryWarnDays: 14},
	}
	findings, err := d.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityCritical {
		t.Fatalf("expected 1 critical finding for an expired cert, got %#v", findings)
	}
}

func TestCertificateExpirationDetector_ExpiringSoon(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := certificateExpirationDetector{now: func() time.Time { return fixedNow }}

	input := detection.Input{
		Asset:  detection.AssetObservation{ID: uuid.New()},
		TLS:    []detection.TLSObservation{{Host: "example.test", Port: 443, NotAfter: fixedNow.AddDate(0, 0, 5)}},
		Config: detection.Config{CertificateExpiryWarnDays: 14},
	}
	findings, _ := d.Detect(context.Background(), input)
	if len(findings) != 1 || findings[0].Severity != detection.SeverityInformational {
		t.Fatalf("expected 1 informational finding for an about-to-expire cert, got %#v", findings)
	}
}

func TestCertificateExpirationDetector_HealthyNoFinding(t *testing.T) {
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := certificateExpirationDetector{now: func() time.Time { return fixedNow }}

	input := detection.Input{
		Asset:  detection.AssetObservation{ID: uuid.New()},
		TLS:    []detection.TLSObservation{{Host: "example.test", Port: 443, NotAfter: fixedNow.AddDate(1, 0, 0)}},
		Config: detection.Config{CertificateExpiryWarnDays: 14},
	}
	findings, _ := d.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a healthy certificate, got %#v", findings)
	}
}

func TestCertificateExpirationDetector_NotEquivalentToCompromised(t *testing.T) {
	// phase8.md §25: expiring-soon must be a strictly lower severity than
	// already-expired — never treated as equivalent.
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := certificateExpirationDetector{now: func() time.Time { return fixedNow }}

	expired, _ := d.Detect(context.Background(), detection.Input{
		Asset: detection.AssetObservation{ID: uuid.New()},
		TLS:   []detection.TLSObservation{{NotAfter: fixedNow.AddDate(0, 0, -1)}},
	})
	soon, _ := d.Detect(context.Background(), detection.Input{
		Asset: detection.AssetObservation{ID: uuid.New()},
		TLS:   []detection.TLSObservation{{NotAfter: fixedNow.AddDate(0, 0, 5)}},
	})
	if expired[0].Severity.Rank() <= soon[0].Severity.Rank() {
		t.Fatalf("expected expired (%s) to rank strictly above expiring-soon (%s)", expired[0].Severity, soon[0].Severity)
	}
}

func TestObsoleteProtocolDetector(t *testing.T) {
	input := detection.Input{
		Asset: detection.AssetObservation{ID: uuid.New()},
		TLS:   []detection.TLSObservation{{Host: "example.test", Version: "TLS 1.0"}},
	}
	findings, _ := obsoleteProtocolDetector{}.Detect(context.Background(), input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for TLS 1.0, got %d", len(findings))
	}

	input.TLS = []detection.TLSObservation{{Host: "example.test", Version: "TLS 1.3"}}
	findings, _ = obsoleteProtocolDetector{}.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for TLS 1.3, got %d", len(findings))
	}
}
