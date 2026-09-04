package detection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ai-recon-platform/internal/httpclient"
)

func TestHTTPFetcher_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Options{})
	fetcher := NewHTTPFetcher(client)

	result, err := fetcher.Fetch(context.Background(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 || string(result.Body) != "hello world" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestHTTPFetcher_TruncatesToMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Options{})
	fetcher := NewHTTPFetcher(client)

	result, err := fetcher.Fetch(context.Background(), srv.URL, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Body) != "0123" {
		t.Fatalf("expected body truncated to 4 bytes, got %q", result.Body)
	}
}
