package detectors

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func TestExposedAPIDocDetector(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/openapi.json", Classification: "openapi", Observed: true}
	findings, err := exposedAPIDocDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	unobserved := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/openapi.json", Classification: "openapi", Observed: false}
	findings, _ = exposedAPIDocDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{unobserved}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a documented-only (never observed) doc, got %d", len(findings))
	}
}

func TestGraphQLInventoryDetector(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/graphql", Classification: "graphql", Observed: true}
	findings, _ := graphQLInventoryDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 || findings[0].Severity != detection.SeverityInformational {
		t.Fatalf("expected 1 informational finding, got %#v", findings)
	}
}

func TestHTTPMethodExposureDetector_DocumentedNotObserved(t *testing.T) {
	ep := detection.EndpointObservation{
		ID: uuid.New(), URL: "https://example.test/api/users/1", Method: "DELETE",
		Documented: true, Observed: false,
	}
	findings, _ := httpMethodExposureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a documented-but-unobserved DELETE, got %d", len(findings))
	}
	// The description must never claim confirmation/exploitability
	// (phase8.md §36/§88).
	if got := findings[0].Description; !containsAll(got, "never actually observed", "documented capability") {
		t.Fatalf("description must clearly state this is unconfirmed, got %q", got)
	}
}

func TestHTTPMethodExposureDetector_ObservedNotReported(t *testing.T) {
	ep := detection.EndpointObservation{
		ID: uuid.New(), URL: "https://example.test/api/users/1", Method: "DELETE",
		Documented: true, Observed: true,
	}
	findings, _ := httpMethodExposureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding once a method is actually observed, got %d", len(findings))
	}
}

func TestHTTPMethodExposureDetector_NeverFlagsGET(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/api/users", Method: "GET", Documented: true, Observed: false}
	findings, _ := httpMethodExposureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected GET to never be flagged, got %d", len(findings))
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
