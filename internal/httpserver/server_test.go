package httpserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/health"
)

func testServerConfig(t *testing.T) config.ServerConfig {
	t.Helper()
	return config.ServerConfig{
		Host:              "127.0.0.1",
		Port:              freePort(t),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       2 * time.Second,
		ShutdownTimeout:   2 * time.Second,
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func TestServerHealthAndReadyEndToEnd(t *testing.T) {
	srv := New(testServerConfig(t), discardLogger(), health.Dependency{Name: "database", Checker: fakeChecker{}})

	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /health, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID response header to be set")
	}

	readyResp, err := http.Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	defer func() { _ = readyResp.Body.Close() }()
	if readyResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /ready, got %d", readyResp.StatusCode)
	}
}

func TestServerHonorsInboundRequestID(t *testing.T) {
	srv := New(testServerConfig(t), discardLogger())
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("X-Request-ID", "test-fixed-id")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Request-ID"); got != "test-fixed-id" {
		t.Errorf("expected inbound request ID to be echoed back, got %q", got)
	}
}

func TestGracefulShutdown(t *testing.T) {
	cfg := testServerConfig(t)
	srv := New(cfg, discardLogger())

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.ListenAndServe() }()

	waitForServer(t, "http://"+cfg.Addr()+"/health")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	select {
	case err := <-serveErrCh:
		if err != nil {
			t.Fatalf("ListenAndServe returned error after shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}

	if _, err := http.Get("http://" + cfg.Addr() + "/health"); err == nil {
		t.Fatal("expected request to fail after server shutdown")
	}
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // url is built from a test-local ephemeral-port address, not external input
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready in time", url)
}
