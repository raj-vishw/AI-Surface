package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

// fakeFetcher is a scripted SafeActiveFetcher for tests — never performs
// a real network request.
type fakeFetcher struct {
	responses map[string]detection.FetchResult
	requested []string
}

func (f *fakeFetcher) Fetch(_ context.Context, rawURL string, _ int) (detection.FetchResult, error) {
	f.requested = append(f.requested, rawURL)
	if r, ok := f.responses[rawURL]; ok {
		return r, nil
	}
	return detection.FetchResult{StatusCode: 404}, nil
}

func safeActiveInput(fetcher detection.SafeActiveFetcher) detection.Input {
	return detection.Input{
		Asset:   detection.AssetObservation{ID: uuid.New(), Scheme: "https", Host: "example.test", Port: 443},
		Mode:    detection.ModeSafeActive,
		Fetcher: fetcher,
		Config:  detection.Config{MaxExcerptLength: 512, MaxResponseSize: 4096},
	}
}

func TestSafeActiveReady_PassiveModeNeverFetches(t *testing.T) {
	fetcher := &fakeFetcher{}
	input := safeActiveInput(fetcher)
	input.Mode = detection.ModePassive

	findings, err := gitExposureDetector{}.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 || len(fetcher.requested) != 0 {
		t.Fatalf("expected zero requests under passive mode, got %d findings, %d requests", len(findings), len(fetcher.requested))
	}
}

func TestGitExposureDetector_ConfirmedByContent(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/.git/HEAD": {StatusCode: 200, Body: []byte("ref: refs/heads/main\n")},
	}}
	input := safeActiveInput(fetcher)

	findings, err := gitExposureDetector{}.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityHigh {
		t.Fatalf("expected 1 high-severity finding, got %#v", findings)
	}
	if len(fetcher.requested) != 1 || fetcher.requested[0] != "https://example.test/.git/HEAD" {
		t.Fatalf("expected exactly one request to the fixed .git/HEAD path, got %v", fetcher.requested)
	}
}

func TestGitExposureDetector_200ButWrongContentNotFlagged(t *testing.T) {
	// A custom 404 page that happens to return 200 must not be
	// mistaken for a real git HEAD file (phase8.md §30).
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/.git/HEAD": {StatusCode: 200, Body: []byte("<html>Not Found</html>")},
	}}
	findings, _ := gitExposureDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if len(findings) != 0 {
		t.Fatalf("expected no finding for non-matching content, got %#v", findings)
	}
}

func TestGitExposureDetector_404NoFinding(t *testing.T) {
	fetcher := &fakeFetcher{}
	findings, _ := gitExposureDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if len(findings) != 0 {
		t.Fatalf("expected no finding on 404, got %#v", findings)
	}
}

func TestEnvFileExposureDetector_RecordsNamesNotValues(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/.env": {StatusCode: 200, ContentType: "text/plain", Body: []byte("DB_PASSWORD=supersecret123\nAPI_KEY=abcdef\n")},
	}}
	findings, err := envFileExposureDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityCritical {
		t.Fatalf("expected 1 critical finding, got %#v", findings)
	}

	data := findings[0].Evidence[0].Data
	names, ok := data["variable_names"].([]any)
	if !ok || len(names) != 2 {
		t.Fatalf("expected 2 variable names recorded, got %#v", data["variable_names"])
	}

	// The actual secret values must never appear anywhere in the evidence.
	for _, v := range data {
		if s, ok := v.(string); ok && (containsAll(s, "supersecret123") || containsAll(s, "abcdef")) {
			t.Fatalf("evidence leaked a secret value: %#v", data)
		}
	}
}

func TestEnvFileExposureDetector_HTMLErrorPageNotFlagged(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/.env": {StatusCode: 200, ContentType: "text/html", Body: []byte("<html>404</html>")},
	}}
	findings, _ := envFileExposureDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an HTML catch-all response, got %#v", findings)
	}
}

func TestSecurityTxtDetector_MissingIsInformational(t *testing.T) {
	fetcher := &fakeFetcher{}
	findings, err := securityTxtDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityInformational {
		t.Fatalf("expected 1 informational finding, got %#v", findings)
	}
}

func TestSecurityTxtDetector_PresentNoFinding(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/.well-known/security.txt": {StatusCode: 200, Body: []byte("Contact: mailto:security@example.test")},
	}}
	findings, _ := securityTxtDetector{}.Detect(context.Background(), safeActiveInput(fetcher))
	if len(findings) != 0 {
		t.Fatalf("expected no finding when security.txt is present, got %#v", findings)
	}
}

func TestErrorDisclosureDetector_RecheckFindsStackTrace(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/broken", StatusCode: 500, Observed: true}
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/broken": {StatusCode: 500, Body: []byte("Traceback (most recent call last):\n  File \"app.py\", line 12\n")},
	}}
	input := safeActiveInput(fetcher)
	input.Endpoints = []detection.EndpointObservation{ep}

	findings, err := errorDisclosureDetector{}.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestErrorDisclosureDetector_WeakKeywordAloneNoFinding(t *testing.T) {
	// phase8.md §62: a weak keyword ("database") alone must not trigger a
	// finding — only a strong structural marker does.
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/broken", StatusCode: 500, Observed: true}
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/broken": {StatusCode: 500, Body: []byte("Sorry, a database error occurred. Please try again later.")},
	}}
	input := safeActiveInput(fetcher)
	input.Endpoints = []detection.EndpointObservation{ep}

	findings, _ := errorDisclosureDetector{}.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a generic error message, got %#v", findings)
	}
}

func TestErrorDisclosureDetector_NeverRechecksNon5xx(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/ok", StatusCode: 200, Observed: true}
	fetcher := &fakeFetcher{}
	input := safeActiveInput(fetcher)
	input.Endpoints = []detection.EndpointObservation{ep}

	_, _ = errorDisclosureDetector{}.Detect(context.Background(), input)
	if len(fetcher.requested) != 0 {
		t.Fatalf("expected no request for a 200 endpoint, got %v", fetcher.requested)
	}
}

func TestDirectoryListingDetector_MarkerDetected(t *testing.T) {
	ep := detection.EndpointObservation{
		ID: uuid.New(), URL: "https://example.test/uploads/", StatusCode: 200, Observed: true,
		Classification: "page", ContentType: "text/html",
	}
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/uploads/": {StatusCode: 200, Body: []byte("<html><title>Index of /uploads</title><body>Parent Directory</a></body></html>")},
	}}
	input := safeActiveInput(fetcher)
	input.Endpoints = []detection.EndpointObservation{ep}

	findings, err := directoryListingDetector{}.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestDirectoryListingDetector_OrdinaryPageNoFinding(t *testing.T) {
	ep := detection.EndpointObservation{
		ID: uuid.New(), URL: "https://example.test/", StatusCode: 200, Observed: true,
		Classification: "page", ContentType: "text/html",
	}
	fetcher := &fakeFetcher{responses: map[string]detection.FetchResult{
		"https://example.test/": {StatusCode: 200, Body: []byte("<html><body>Welcome</body></html>")},
	}}
	input := safeActiveInput(fetcher)
	input.Endpoints = []detection.EndpointObservation{ep}

	findings, _ := directoryListingDetector{}.Detect(context.Background(), input)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for an ordinary page, got %#v", findings)
	}
}
