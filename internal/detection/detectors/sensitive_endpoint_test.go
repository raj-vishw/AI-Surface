package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func TestSensitiveEndpointDetector_AdminPath(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/admin/", Path: "/admin/", StatusCode: 200, Observed: true}
	findings, err := sensitiveEndpointDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityInformational {
		t.Fatalf("expected 1 informational finding, got %#v", findings)
	}
}

func TestSensitiveEndpointDetector_OrdinaryPathIgnored(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/products", Path: "/products", StatusCode: 200, Observed: true}
	findings, _ := sensitiveEndpointDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an ordinary path, got %d", len(findings))
	}
}

func TestSensitiveEndpointDetector_UnobservedIgnored(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/admin/", Path: "/admin/", Observed: false}
	findings, _ := sensitiveEndpointDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an unobserved candidate, got %d", len(findings))
	}
}

func TestBackupFileDetector(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/config.php.bak", Path: "/config.php.bak", StatusCode: 200, Observed: true}
	findings, err := backupFileDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a .bak file, got %d", len(findings))
	}

	notBackup := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/config.php", Path: "/config.php", StatusCode: 200, Observed: true}
	findings, _ = backupFileDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{notBackup}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a non-backup path, got %d", len(findings))
	}
}

func TestExposedServiceDetector(t *testing.T) {
	input := detection.Input{
		Asset:    detection.AssetObservation{ID: uuid.New()},
		Services: []detection.ServiceObservation{{Host: "example.test", Port: 5432, State: "OPEN", Service: "DATABASE"}},
	}
	findings, err := exposedServiceDetector{}.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for open Postgres port, got %d", len(findings))
	}

	input.Services = []detection.ServiceObservation{{Host: "example.test", Port: 80, State: "OPEN", Service: "HTTP"}}
	findings, _ = exposedServiceDetector{}.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an ordinary HTTP port, got %d", len(findings))
	}

	input.Services = []detection.ServiceObservation{{Host: "example.test", Port: 5432, State: "CLOSED", Service: "DATABASE"}}
	findings, _ = exposedServiceDetector{}.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a closed port, got %d", len(findings))
	}
}
