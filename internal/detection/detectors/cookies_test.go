package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func endpointWithCookies(url string, cookies []map[string]any) detection.EndpointObservation {
	return detection.EndpointObservation{
		ID: uuid.New(), URL: url, Observed: true, StatusCode: 200,
		Metadata: map[string]any{"discovery_method": "http", "cookie_attributes": toAnySlice(cookies)},
	}
}

func toAnySlice(cookies []map[string]any) []any {
	out := make([]any, len(cookies))
	for i, c := range cookies {
		out[i] = c
	}
	return out
}

func TestCookieDetector_SecureMissingHttpOnlyMissing(t *testing.T) {
	ep := endpointWithCookies("https://example.test/", []map[string]any{
		{"name": "session", "secure": false, "httponly": false, "samesite": "Lax"},
	})
	findings, err := cookieDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
}

func TestCookieDetector_SameSiteNoneWithoutSecure(t *testing.T) {
	ep := endpointWithCookies("https://example.test/", []map[string]any{
		{"name": "tracking", "secure": false, "httponly": true, "samesite": "None"},
	})
	findings, _ := cookieDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 || findings[0].Severity != detection.SeverityMedium {
		t.Fatalf("expected 1 medium-severity finding, got %#v", findings)
	}
}

func TestCookieDetector_ProperlyConfiguredNoFinding(t *testing.T) {
	ep := endpointWithCookies("https://example.test/", []map[string]any{
		{"name": "session", "secure": true, "httponly": true, "samesite": "Strict"},
	})
	findings, _ := cookieDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a properly configured cookie, got %#v", findings)
	}
}

func TestCookieDetector_NeverStoresValue(t *testing.T) {
	ep := endpointWithCookies("https://example.test/", []map[string]any{
		{"name": "session", "secure": false, "httponly": false, "samesite": ""},
	})
	findings, _ := cookieDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	for _, e := range findings[0].Evidence {
		for k := range e.Data {
			if k == "value" {
				t.Fatalf("evidence must never contain a cookie value key, found one: %#v", e.Data)
			}
		}
	}
}

func TestCookieDetector_InsecureAttributeOnPlainHTTPNotFlaggedForSecure(t *testing.T) {
	// Secure is meaningless (and commonly absent) on plain HTTP — must not
	// be flagged there, mirroring the HSTS detector's own HTTPS-only rule.
	ep := endpointWithCookies("http://example.test/", []map[string]any{
		{"name": "session", "secure": false, "httponly": true, "samesite": "Lax"},
	})
	findings, _ := cookieDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no Secure-missing finding on plain HTTP, got %#v", findings)
	}
}
