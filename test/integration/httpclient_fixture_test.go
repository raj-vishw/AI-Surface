// Package integration holds cross-cutting tests that exercise more than
// one internal package together. Tests here that need real infrastructure
// (PostgreSQL, Redis) are gated behind the "integration" build tag and
// require `make dev-up` first; tests that only need a local HTTP test
// server (like this one) run as part of the normal `go test ./...` suite,
// per the master specification's requirement that CI must not depend on
// Internet-reachable services.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ai-recon-platform/internal/httpclient"
)

type fixture struct {
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

func loadFixture(t *testing.T, path string) fixture {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path, not user input
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return f
}

// TestHTTPClientAgainstFixture serves the fixture's body from a local
// httptest server and verifies internal/httpclient reports the exact
// status, content type, body, and body hash — deterministic, no external
// dependency.
func TestHTTPClientAgainstFixture(t *testing.T) {
	f := loadFixture(t, "../fixtures/sample_response.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(f.Body))
	}))
	defer server.Close()

	client := httpclient.New(httpclient.Options{
		Timeout:               2 * time.Second,
		MaxIdleConnections:    10,
		MaxConnectionsPerHost: 10,
		MaxResponseSize:       1 << 20,
		MaxRedirects:          5,
	})

	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.ContentType != f.ContentType {
		t.Errorf("expected content type %q, got %q", f.ContentType, resp.ContentType)
	}
	if string(resp.Body) != f.Body {
		t.Errorf("expected body %q, got %q", f.Body, resp.Body)
	}

	sum := sha256.Sum256([]byte(f.Body))
	expectedHash := hex.EncodeToString(sum[:])
	if resp.BodySHA256 != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, resp.BodySHA256)
	}
}
