package http

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/discovery/model"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/httpclient"
)

// Scanner executes HTTP discovery against a single authorized target,
// using bounded concurrency and the Phase 1 HTTP client for every request.
type Scanner struct {
	client *httpclient.Client
	logger *slog.Logger
	cfg    Config
}

// NewScanner builds a Scanner. client should normally be built with
// NewClientForScope so its redirect policy is bound to the same scope
// passed to Scan.
func NewScanner(client *httpclient.Client, logger *slog.Logger, cfg Config) *Scanner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Scanner{client: client, logger: logger, cfg: cfg}
}

// NewClientForScope builds an internal/httpclient.Client whose redirect
// policy is bound to scope, so it can never connect to an out-of-scope
// host even transiently via a redirect (phase3.md §24). This reuses the
// Phase 1 HTTP client's existing Options.AllowRedirectTo extension point —
// it is not a second transport implementation (phase3.md §12).
func NewClientForScope(cfg Config, scope *ScopeValidator) *httpclient.Client {
	maxRedirects := cfg.MaxRedirects
	if !cfg.FollowRedirects {
		maxRedirects = 0
	}
	return httpclient.New(httpclient.Options{
		Timeout:         cfg.Timeout,
		MaxResponseSize: cfg.MaxResponseSize,
		MaxRedirects:    maxRedirects,
		AllowRedirectTo: scope.Allowed,
	})
}

// ScanRequest describes one discovery run.
type ScanRequest struct {
	TargetID    uuid.UUID
	TargetType  domaintarget.Type
	TargetValue string
	Paths       []string
}

// Scan generates the candidate list for req (see GenerateCandidates), then
// requests every candidate with concurrency bounded to cfg.MaxConcurrency.
// It respects ctx cancellation throughout: once ctx is done, no new
// request is started and in-flight requests are cancelled via their own
// per-request context, which is derived from ctx — Ctrl+C therefore stops
// the scan promptly with no goroutine leaks (every goroutine this method
// starts is joined via the WaitGroup before Scan returns).
//
// Scan never distinguishes dry-run — callers must not invoke Scan at all
// when security.dry_run is set; see internal/discovery/service and
// phase3.md §45.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest, scope *ScopeValidator) (*model.Summary, error) {
	scanID := uuid.New()
	start := time.Now()

	candidates, err := GenerateCandidates(req.TargetType, req.TargetValue, s.cfg, req.Paths, scope)
	if err != nil {
		return nil, err
	}

	results := make([]model.Result, len(candidates))
	sem := make(chan struct{}, maxInt(s.cfg.MaxConcurrency, 1))
	var wg sync.WaitGroup

	for i, c := range candidates {
		wg.Add(1)
		go func(i int, c Candidate) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = cancelledResult(scanID, req.TargetID, c, ctx.Err())
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[i] = cancelledResult(scanID, req.TargetID, c, ctx.Err())
				return
			}

			resp, doErr := s.client.Do(ctx, buildRequest(c))
			result := buildResult(scanID, req.TargetID, c, resp, doErr, s.cfg, scope)
			results[i] = result
			s.logResult(result)
		}(i, c)
	}

	wg.Wait()

	return summarize(scanID, req.TargetID, req.TargetValue, results, time.Since(start)), nil
}

func cancelledResult(scanID, targetID uuid.UUID, c Candidate, err error) model.Result {
	return model.Result{
		ScanID: scanID, TargetID: targetID, Method: c.Method, URL: c.URL,
		Error: err.Error(), ObservedAt: time.Now().UTC(),
	}
}

func (s *Scanner) logResult(r model.Result) {
	if r.Error != "" {
		s.logger.Warn("http_discovery_request_failed",
			"scan_id", r.ScanID, "target_id", r.TargetID, "url", r.URL, "method", r.Method, "error", r.Error)
		return
	}
	s.logger.Info("http_discovery_request_completed",
		"scan_id", r.ScanID, "target_id", r.TargetID, "url", r.URL, "method", r.Method,
		"discovery_method", "http", "status_code", r.StatusCode, "duration", r.Duration,
		"result", r.ServiceType, "ai_candidate", r.AIEndpointCandidate,
	)
}

// summarize aggregates results into the scan summary described by
// phase3.md §27. An AI candidate is counted in both APICandidates and
// AICandidates (every AI candidate this phase detects is JSON-shaped, and
// therefore also an API candidate).
func summarize(scanID, targetID uuid.UUID, target string, results []model.Result, duration time.Duration) *model.Summary {
	summary := &model.Summary{
		ScanID: scanID, TargetID: targetID, Target: target,
		URLsAttempted: len(results), Duration: duration, Results: results,
	}

	for _, r := range results {
		if r.Error != "" {
			summary.Failed++
			summary.Errors++
			continue
		}
		summary.Successful++

		if len(r.RedirectChain) > 0 {
			summary.Redirects++
		}

		switch r.ServiceType {
		case model.ServiceAICandidate:
			summary.AICandidates++
			summary.APICandidates++
			summary.HTTPEndpoints++
		case model.ServiceAPI, model.ServiceJSONAPI:
			summary.APICandidates++
			summary.HTTPEndpoints++
		case model.ServiceUnknown:
			if !r.RedirectBlocked {
				summary.HTTPEndpoints++
			}
		default:
			summary.HTTPEndpoints++
		}
	}

	return summary
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
