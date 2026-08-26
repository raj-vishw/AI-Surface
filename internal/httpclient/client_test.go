package httpclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, overrides func(*Options)) *Client {
	t.Helper()
	opts := Options{
		Timeout:               2 * time.Second,
		MaxIdleConnections:    10,
		MaxConnectionsPerHost: 10,
		MaxResponseSize:       1024,
		MaxRedirects:          5,
	}
	if overrides != nil {
		overrides(&opts)
	}
	return New(opts)
}

func TestGetRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != "hello" {
		t.Errorf("expected body %q, got %q", "hello", resp.Body)
	}
}

func TestPostRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "payload" {
			t.Errorf("expected body %q, got %q", "payload", body)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Post(context.Background(), server.URL, strings.NewReader("payload"), nil)
	if err != nil {
		t.Fatalf("Post() returned error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
}

func TestRequestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testClient(t, func(o *Options) { o.Timeout = 20 * time.Millisecond })

	start := time.Now()
	_, err := client.Get(context.Background(), server.URL, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed > time.Second {
		t.Errorf("timeout took too long to trigger: %s", elapsed)
	}
}

func TestRequestCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testClient(t, func(o *Options) { o.Timeout = 5 * time.Second })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := client.Get(ctx, server.URL, nil)
	if err == nil {
		t.Fatal("expected an error from a cancelled request")
	}
}

func TestRedirectHandling(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Get(context.Background(), server.URL+"/start", nil)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected final status 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != "target" {
		t.Errorf("expected redirected body %q, got %q", "target", resp.Body)
	}
	if !strings.HasSuffix(resp.URL, "/target") {
		t.Errorf("expected final URL to end in /target, got %s", resp.URL)
	}
}

func TestRedirectLimit(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := testClient(t, func(o *Options) { o.MaxRedirects = 3 })
	resp, err := client.Get(context.Background(), server.URL+"/loop", nil)
	if err != nil {
		t.Fatalf("expected redirect limit to stop cleanly (last response returned), got error: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected the last (302) response to be returned, got %d", resp.StatusCode)
	}
	// initial request + MaxRedirects follow-ups
	if hits > 4 {
		t.Errorf("expected at most 4 hits (1 + MaxRedirects), got %d", hits)
	}
}

func TestResponseSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 4096)) // exceeds the 1024-byte test limit
	}))
	defer server.Close()

	client := testClient(t, nil)
	_, err := client.Get(context.Background(), server.URL, nil)
	if err == nil {
		t.Fatal("expected an error for a response exceeding MaxResponseSize")
	}
}

func TestRequestAndResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Custom"); got != "value" {
			t.Errorf("expected request header X-Custom=value, got %q", got)
		}
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testClient(t, nil)
	headers := http.Header{}
	headers.Set("X-Custom", "value")

	resp, err := client.Get(context.Background(), server.URL, headers)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if got := resp.Headers.Get("X-Response-Header"); got != "response-value" {
		t.Errorf("expected response header to be captured, got %q", got)
	}
}

func TestContentTypeCaptured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if resp.ContentType != "application/json" {
		t.Errorf("expected content type application/json, got %q", resp.ContentType)
	}
}

func TestResponseBodyHashing(t *testing.T) {
	body := "the quick brown fox"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}

	sum := sha256.Sum256([]byte(body))
	expected := hex.EncodeToString(sum[:])
	if resp.BodySHA256 != expected {
		t.Errorf("expected hash %s, got %s", expected, resp.BodySHA256)
	}
}

func TestConnectionReuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := testClient(t, nil)

	// First request establishes a connection.
	if _, err := client.Get(context.Background(), server.URL, nil); err != nil {
		t.Fatalf("first Get() returned error: %v", err)
	}

	var reused bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			reused = info.Reused
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	if _, err := client.Get(ctx, server.URL, nil); err != nil {
		t.Fatalf("second Get() returned error: %v", err)
	}
	if !reused {
		t.Error("expected the second request to reuse the pooled connection")
	}
}

func TestNon2xxResponsesAreNotErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client := testClient(t, nil)
	resp, err := client.Get(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("expected no error for a 404 response, got: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestServerConnectionFailure(t *testing.T) {
	// Reserve a port, then close the listener so nothing is bound there.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	client := testClient(t, nil)
	_, err = client.Get(context.Background(), "http://"+addr, nil)
	if err == nil {
		t.Fatal("expected an error connecting to a closed port")
	}
}
