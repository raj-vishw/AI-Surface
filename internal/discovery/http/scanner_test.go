package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	domaintarget "ai-recon-platform/internal/domain/target"
)

func TestScanner_BoundedConcurrency(t *testing.T) {
	var active int32
	var maxObserved int32

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&maxObserved)
			if n <= old || atomic.CompareAndSwapInt32(&maxObserved, old, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	const limit = 3
	scope := mustScope(t, srv.URL)
	cfg := Config{Timeout: 2 * time.Second, MaxConcurrency: limit, MaxResponseSize: 1024, FollowRedirects: true, MaxRedirects: 5, Methods: []string{"GET"}, Schemes: []string{"http"}}
	scanner := NewScanner(NewClientForScope(cfg, scope), nil, cfg)

	paths := make([]string, 10)
	for i := range paths {
		paths[i] = fmt.Sprintf("/p%d", i)
	}

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetType: domaintarget.TypeURL, TargetValue: srv.URL, Paths: paths,
	}, scope)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if summary.Successful != len(paths) {
		t.Errorf("Successful = %d, want %d", summary.Successful, len(paths))
	}
	if got := atomic.LoadInt32(&maxObserved); got > limit {
		t.Errorf("observed %d concurrent in-flight requests, want <= %d", got, limit)
	}
}

func TestScanner_CancellationStopsPromptlyWithoutLeaks(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	scope := mustScope(t, srv.URL)
	cfg := Config{Timeout: 5 * time.Second, MaxConcurrency: 2, MaxResponseSize: 1024, FollowRedirects: true, MaxRedirects: 5, Methods: []string{"GET"}, Schemes: []string{"http"}}
	scanner := NewScanner(NewClientForScope(cfg, scope), nil, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	paths := make([]string, 20)
	for i := range paths {
		paths[i] = fmt.Sprintf("/p%d", i)
	}

	start := time.Now()
	// Scan's own internal sync.WaitGroup.Wait() means it cannot return
	// until every goroutine it started has finished — so a prompt return
	// here is itself evidence of no leaked goroutines (phase3.md §44).
	summary, err := scanner.Scan(ctx, ScanRequest{
		TargetType: domaintarget.TypeURL, TargetValue: srv.URL, Paths: paths,
	}, scope)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Scan() returned an error (cancellation should surface as per-result errors, not a Scan()-level error): %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Scan() took too long to return after cancellation: %v", elapsed)
	}
	if summary.Successful == len(paths) {
		t.Error("expected cancellation to prevent at least some requests from completing")
	}
}

func TestScanner_FailureIsolation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/hang", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond) // longer than cfg.Timeout below
		_, _ = w.Write([]byte("late"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	scope := mustScope(t, srv.URL)
	cfg := Config{Timeout: 50 * time.Millisecond, MaxConcurrency: 5, MaxResponseSize: 1024, FollowRedirects: true, MaxRedirects: 5, Methods: []string{"GET"}, Schemes: []string{"http"}}
	scanner := NewScanner(NewClientForScope(cfg, scope), nil, cfg)

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetType: domaintarget.TypeURL, TargetValue: srv.URL, Paths: []string{"/ok", "/hang"},
	}, scope)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if summary.Successful != 1 {
		t.Errorf("Successful = %d, want 1 (one URL timing out must not prevent the other from succeeding)", summary.Successful)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}
}

func TestScanner_OutOfScopeRedirectNotFollowed(t *testing.T) {
	var outOfScopeRequestReceived int32

	// ScopeValidator matches on hostname only (deliberately — see its doc
	// comment: a redirect to the same host on a different port is not a
	// scope violation). To exercise a genuine cross-host redirect without
	// any external network dependency (phase3.md §33), the "out of scope"
	// fixture is bound to a second, distinct loopback address
	// (127.0.0.2 — part of the 127.0.0.0/8 loopback block, routable
	// locally without any real DNS or Internet access) rather than merely
	// a different port on 127.0.0.1.
	outOfScopeListener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 is not routable in this environment: %v", err)
	}
	outOfScope := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&outOfScopeRequestReceived, 1)
		_, _ = w.Write([]byte("should never be reached"))
	}))
	outOfScope.Listener.Close() //nolint:errcheck,gosec // replaced with the 127.0.0.2 listener below
	outOfScope.Listener = outOfScopeListener
	outOfScope.Start()
	defer outOfScope.Close()

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScope.URL+"/", http.StatusFound)
	}))
	defer inScope.Close()

	scope := mustScope(t, inScope.URL)
	cfg := Config{Timeout: 2 * time.Second, MaxConcurrency: 2, MaxResponseSize: 1024, FollowRedirects: true, MaxRedirects: 5, Methods: []string{"GET"}, Schemes: []string{"http"}}
	scanner := NewScanner(NewClientForScope(cfg, scope), nil, cfg)

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetType: domaintarget.TypeURL, TargetValue: inScope.URL, Paths: []string{"/"},
	}, scope)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if atomic.LoadInt32(&outOfScopeRequestReceived) != 0 {
		t.Fatal("the out-of-scope host was connected to — scope validation must block the redirect before any request is sent to it")
	}
	if len(summary.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(summary.Results))
	}
	result := summary.Results[0]
	if !result.RedirectBlocked {
		t.Error("expected RedirectBlocked to be true")
	}
	if !result.Skipped {
		t.Error("expected the blocked-redirect result to be marked Skipped (never persisted)")
	}
	if result.SkippedReason == "" {
		t.Error("expected a non-empty SkippedReason explaining why (phase3.md §24: never silently discard this)")
	}
}

func TestScanner_AICandidateDetectedEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"test-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	scope := mustScope(t, srv.URL)
	cfg := Config{
		Timeout: 2 * time.Second, MaxConcurrency: 2, MaxResponseSize: 1024, FollowRedirects: true, MaxRedirects: 5,
		Methods: []string{"GET"}, Schemes: []string{"http"}, DetectAIEndpoints: true,
	}
	scanner := NewScanner(NewClientForScope(cfg, scope), nil, cfg)

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetType: domaintarget.TypeURL, TargetValue: srv.URL, Paths: []string{"/v1/chat/completions"},
	}, scope)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if len(summary.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(summary.Results))
	}
	result := summary.Results[0]
	if !result.AIEndpointCandidate {
		t.Error("expected the AI-shaped response to be detected as an AI endpoint candidate")
	}
	if summary.AICandidates != 1 {
		t.Errorf("summary.AICandidates = %d, want 1", summary.AICandidates)
	}
}
