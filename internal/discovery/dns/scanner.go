package dns

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	discoveryhttp "ai-recon-platform/internal/discovery/http"
)

// Scanner executes DNS record discovery and subdomain enumeration, using
// bounded concurrency and a pluggable Resolver — no coupling to the CLI, a
// future REST API, or a future worker (phase5.md §6).
//
// Scope validation reuses internal/discovery/http.ScopeValidator directly
// — unlike Phase 4's network discovery (where that would have been
// semantically wrong for IP/CIDR targets), DNS scope is exactly the same
// concept HTTP discovery already implements: exact-hostname-or-subdomain
// matching against a domain (phase5.md §43's "label-aware domain suffix
// matching" is precisely what ScopeValidator already does).
type Scanner struct {
	resolver Resolver
	logger   *slog.Logger
	cfg      Config
}

// NewScanner builds a Scanner.
func NewScanner(resolver Resolver, logger *slog.Logger, cfg Config) *Scanner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Scanner{resolver: resolver, logger: logger, cfg: cfg}
}

// ScanRequest describes one discovery run.
type ScanRequest struct {
	TargetID       uuid.UUID
	Domain         string // normalized target domain
	RecordTypes    []RecordType
	SubdomainWords []string // empty = skip subdomain enumeration entirely
}

// Scan performs record discovery for req.Domain, then (if
// req.SubdomainWords is non-empty) wildcard detection and subdomain
// enumeration, then (if configured) PTR lookups for every discovered
// A/AAAA address. Every phase is bounded to cfg.MaxConcurrency concurrent
// resolver calls and respects ctx cancellation throughout — the same
// leak-free guarantee internal/discovery/http and .../network document:
// every goroutine is joined via a sync.WaitGroup before its phase
// returns.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest, scope *discoveryhttp.ScopeValidator) (*Summary, error) {
	scanID := uuid.New()
	start := time.Now()

	limiter := newRateLimiter(s.cfg.RequestsPerSecond)
	if limiter != nil {
		defer limiter.Stop()
	}

	recordResults := s.resolveRecordTypes(ctx, scanID, req.TargetID, req.Domain, req.RecordTypes, limiter)

	var (
		wildcard         *WildcardDetection
		subdomainResults []SubdomainResult
	)
	if len(req.SubdomainWords) > 0 {
		candidates, err := GenerateCandidates(req.Domain, req.SubdomainWords, s.cfg.Subdomains.MaxDepth, s.cfg.Subdomains.MaxCandidates)
		if err != nil {
			return nil, err
		}
		candidates = filterInScope(candidates, scope)

		var baseline WildcardDetection
		if s.cfg.Subdomains.WildcardDetection {
			detected, err := DetectWildcard(ctx, s.resolver, req.Domain, req.RecordTypes)
			if err == nil { // a wildcard-probe failure just means "couldn't determine" — never abort the scan over it
				baseline = detected
				wildcard = &detected
			}
		}

		subdomainResults = s.resolveSubdomains(ctx, scanID, req.TargetID, candidates, req.RecordTypes, baseline, limiter)
	}

	var ptrResults []RecordResult
	if s.cfg.ReversePTR {
		ips := discoveredIPs(recordResults, subdomainResults)
		ptrResults = s.resolvePTRs(ctx, scanID, req.TargetID, ips, limiter)
		recordResults = append(recordResults, ptrResults...)
	}

	for _, r := range recordResults {
		s.logRecordResult(r)
	}

	return summarize(scanID, req.TargetID, req.Domain, recordResults, subdomainResults, wildcard, time.Since(start)), nil
}

// resolveRecordTypes queries every record type for name with bounded
// concurrency.
func (s *Scanner) resolveRecordTypes(ctx context.Context, scanID, targetID uuid.UUID, name string, types []RecordType, limiter *rateLimiter) []RecordResult {
	results := make([]RecordResult, len(types))
	sem := make(chan struct{}, maxInt(s.cfg.MaxConcurrency, 1))
	var wg sync.WaitGroup

	for i, rt := range types {
		wg.Add(1)
		go func(i int, rt RecordType) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = cancelledRecordResult(scanID, targetID, name, rt, ctx.Err())
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[i] = cancelledRecordResult(scanID, targetID, name, rt, ctx.Err())
				return
			}
			if !awaitLimiter(ctx, limiter) {
				results[i] = cancelledRecordResult(scanID, targetID, name, rt, ctx.Err())
				return
			}

			results[i] = s.queryOne(ctx, scanID, targetID, name, rt)
		}(i, rt)
	}
	wg.Wait()
	return results
}

// resolveSubdomains resolves every candidate against types (first type to
// resolve wins, same short-circuit resolveAny uses for wildcard probing)
// with bounded concurrency.
func (s *Scanner) resolveSubdomains(ctx context.Context, scanID, targetID uuid.UUID, candidates []SubdomainCandidate, types []RecordType, wildcard WildcardDetection, limiter *rateLimiter) []SubdomainResult {
	results := make([]SubdomainResult, len(candidates))
	sem := make(chan struct{}, maxInt(s.cfg.MaxConcurrency, 1))
	var wg sync.WaitGroup

	for i, c := range candidates {
		wg.Add(1)
		go func(i int, c SubdomainCandidate) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = SubdomainResult{ScanID: scanID, TargetID: targetID, Name: c.Name, Source: c.Source, State: StateError, ObservedAt: time.Now().UTC()}
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil || !awaitLimiter(ctx, limiter) {
				results[i] = SubdomainResult{ScanID: scanID, TargetID: targetID, Name: c.Name, Source: c.Source, State: StateError, ObservedAt: time.Now().UTC()}
				return
			}

			results[i] = s.resolveSubdomain(ctx, scanID, targetID, c, types, wildcard)
		}(i, c)
	}
	wg.Wait()
	return results
}

func (s *Scanner) resolveSubdomain(ctx context.Context, scanID, targetID uuid.UUID, c SubdomainCandidate, types []RecordType, wildcard WildcardDetection) SubdomainResult {
	result := SubdomainResult{ScanID: scanID, TargetID: targetID, Name: c.Name, Source: c.Source, Confidence: c.Confidence, ObservedAt: time.Now().UTC()}

	for _, rt := range types {
		lookup, err := s.resolver.Lookup(ctx, c.Name, rt)
		if err != nil {
			result.State = classifyTransportError(err)
			continue
		}
		state := classify(lookup)
		if state == StateResolved {
			values := make([]string, len(lookup.Records))
			for i, r := range lookup.Records {
				values[i] = r.Value
			}
			result.State = StateResolved
			result.Records = append(result.Records, lookup.Records...)
			result.WildcardAffected = wildcard.MatchesWildcard(values)
			result.HTTPCandidate = true
			return result
		}
		if state == StateNXDOMAIN {
			result.State = StateNXDOMAIN
			return result // NXDOMAIN on one type means the name doesn't exist at all — no point trying other types
		}
		if result.State == "" {
			result.State = state
		}
	}
	if result.State == "" {
		result.State = StateNoAnswer
	}
	return result
}

func (s *Scanner) resolvePTRs(ctx context.Context, scanID, targetID uuid.UUID, ips []string, limiter *rateLimiter) []RecordResult {
	results := make([]RecordResult, len(ips))
	sem := make(chan struct{}, maxInt(s.cfg.MaxConcurrency, 1))
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = cancelledRecordResult(scanID, targetID, ip, TypePTR, ctx.Err())
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil || !awaitLimiter(ctx, limiter) {
				results[i] = cancelledRecordResult(scanID, targetID, ip, TypePTR, ctx.Err())
				return
			}

			start := time.Now()
			lookup, err := s.resolver.LookupPTR(ctx, ip)
			result := RecordResult{ScanID: scanID, TargetID: targetID, Name: ip, Type: TypePTR, Duration: time.Since(start), ObservedAt: time.Now().UTC()}
			if err != nil {
				result.State = classifyTransportError(err)
				result.Error = err.Error()
			} else {
				result.State = classify(lookup)
				result.Records = lookup.Records
			}
			results[i] = result
		}(i, ip)
	}
	wg.Wait()
	return results
}

func (s *Scanner) queryOne(ctx context.Context, scanID, targetID uuid.UUID, name string, rt RecordType) RecordResult {
	start := time.Now()
	lookup, err := s.resolver.Lookup(ctx, name, rt)
	result := RecordResult{ScanID: scanID, TargetID: targetID, Name: name, Type: rt, Duration: time.Since(start), ObservedAt: time.Now().UTC()}
	if err != nil {
		result.State = classifyTransportError(err)
		result.Error = err.Error()
		return result
	}
	result.State = classify(lookup)
	result.Records = lookup.Records
	return result
}

func cancelledRecordResult(scanID, targetID uuid.UUID, name string, rt RecordType, err error) RecordResult {
	e := ""
	if err != nil {
		e = err.Error()
	}
	return RecordResult{ScanID: scanID, TargetID: targetID, Name: name, Type: rt, State: StateError, Error: e, ObservedAt: time.Now().UTC()}
}

// filterInScope drops any candidate whose name fails scope — defense in
// depth, since every candidate is derived directly from the target
// domain; the caller (internal/discovery/service) has already validated
// the domain itself is authorized (phase5.md §42/§43).
func filterInScope(candidates []SubdomainCandidate, scope *discoveryhttp.ScopeValidator) []SubdomainCandidate {
	if scope == nil {
		return candidates
	}
	var inScope []SubdomainCandidate
	for _, c := range candidates {
		if scope.AllowedURL("dns://" + c.Name) {
			inScope = append(inScope, c)
		}
	}
	return inScope
}

// discoveredIPs collects the unique set of IP addresses from every A/AAAA
// record across both record and subdomain results, in deterministic
// (sorted) order.
func discoveredIPs(records []RecordResult, subdomains []SubdomainResult) []string {
	seen := make(map[string]bool)
	var ips []string
	add := func(rs []Record) {
		for _, r := range rs {
			if (r.Type == TypeA || r.Type == TypeAAAA) && !seen[r.Value] {
				seen[r.Value] = true
				ips = append(ips, r.Value)
			}
		}
	}
	for _, r := range records {
		add(r.Records)
	}
	for _, sd := range subdomains {
		add(sd.Records)
	}
	return ips
}

func (s *Scanner) logRecordResult(r RecordResult) {
	if r.Error != "" {
		s.logger.Warn("dns_query_failed",
			"scan_id", r.ScanID, "target_id", r.TargetID, "name", r.Name, "record_type", r.Type,
			"resolution_state", r.State, "error", r.Error)
		return
	}
	s.logger.Info("dns_query_completed",
		"scan_id", r.ScanID, "target_id", r.TargetID, "name", r.Name, "record_type", r.Type,
		"resolution_state", r.State, "duration", r.Duration, "records", len(r.Records))
}

func summarize(scanID, targetID uuid.UUID, target string, records []RecordResult, subdomains []SubdomainResult, wildcard *WildcardDetection, duration time.Duration) *Summary {
	summary := &Summary{
		ScanID: scanID, TargetID: targetID, Target: target,
		RecordCounts: make(map[RecordType]int),
		Duration:     duration, RecordResults: records, SubdomainResults: subdomains, Wildcard: wildcard,
	}

	summary.NamesQueried = len(records)
	for _, r := range records {
		switch r.State {
		case StateResolved:
			summary.Resolved++
			for _, rec := range r.Records {
				summary.RecordCounts[rec.Type]++
			}
		case StateNXDOMAIN:
			summary.NXDOMAIN++
		case StateNoAnswer:
			summary.NoAnswer++
		case StateTimeout:
			summary.Timeouts++
		case StateError:
			summary.Errors++
		}
	}

	for _, sd := range subdomains {
		if sd.Succeeded() {
			summary.SubdomainsDiscovered++
		}
	}
	if wildcard != nil && wildcard.Detected {
		summary.WildcardDetected = true
	}

	return summary
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// rateLimiter paces resolver calls to at most cfg.RequestsPerSecond per
// second in aggregate — a safety/stability control (phase5.md §41), never
// randomized/stealth timing. nil (from newRateLimiter with rps <= 0) means
// unlimited.
type rateLimiter struct {
	ticker *time.Ticker
	C      <-chan time.Time
}

func newRateLimiter(requestsPerSecond float64) *rateLimiter {
	if requestsPerSecond <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / requestsPerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	t := time.NewTicker(interval)
	return &rateLimiter{ticker: t, C: t.C}
}

func (r *rateLimiter) Stop() { r.ticker.Stop() }

// awaitLimiter blocks until limiter allows the next call (or ctx ends),
// returning false only on context cancellation. A nil limiter always
// returns true immediately.
func awaitLimiter(ctx context.Context, limiter *rateLimiter) bool {
	if limiter == nil {
		return true
	}
	select {
	case <-limiter.C:
		return true
	case <-ctx.Done():
		return false
	}
}
