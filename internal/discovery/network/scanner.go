package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// Scanner executes TCP connect discovery, using bounded concurrency and
// Go's standard net.Dialer — no raw sockets, no privileged access required
// (phase4.md §49). It never persists anything; see
// internal/discovery/service for the layer that normalizes Results into
// Phase 2 assets/endpoints/evidence.
//
// Scope validation uses ScopeChecker (see scope.go) — address-membership
// based, not the hostname/subdomain matching internal/discovery/http uses,
// because that would be semantically wrong for IP/CIDR targets.
type Scanner struct {
	logger *slog.Logger
	cfg    Config
	dialer *net.Dialer
	// dial defaults to dialer.DialContext. It exists as a seam so tests
	// can deterministically observe/control concurrency and timing (a
	// bare loopback TCP handshake completes in microseconds regardless of
	// how the server paces Accept(), so server-side instrumentation alone
	// can't reliably exercise MaxConcurrency/cancellation — see
	// scanner_test.go) without changing Scanner's public API.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewScanner builds a Scanner.
func NewScanner(logger *slog.Logger, cfg Config) *Scanner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	return &Scanner{
		logger: logger,
		cfg:    cfg,
		dialer: dialer,
		dial:   dialer.DialContext,
	}
}

// ScanRequest describes one discovery run: already-expanded hosts (see
// ExpandTarget) and already-parsed ports (see ParsePorts) to scan every
// combination of.
type ScanRequest struct {
	TargetID uuid.UUID
	Target   string // the original target value, for Summary.Target
	Hosts    []string
	Ports    []int
}

// Scan connects to every host:port combination in req, bounded to
// cfg.MaxConcurrency concurrent attempts and (if configured) paced to
// cfg.RequestsPerSecond. scope is checked for every combination
// immediately before connecting — never assumed from expansion alone
// (phase4.md §13) — a combination that fails scope becomes a Skipped
// result, never a TCP connection attempt.
//
// Scan respects ctx cancellation throughout: once ctx is done, no new
// connection is started, and every goroutine it started is joined via a
// sync.WaitGroup before Scan returns — the same leak-free guarantee
// internal/discovery/http.Scanner.Scan documents (phase4.md §16/§41).
func (s *Scanner) Scan(ctx context.Context, req ScanRequest, scope *ScopeChecker) (*Summary, error) {
	scanID := uuid.New()
	start := time.Now()

	jobs := buildJobs(req.Hosts, req.Ports)

	results := make([]PortResult, len(jobs))
	sem := make(chan struct{}, maxInt(s.cfg.MaxConcurrency, 1))

	var limiter *rateLimiter
	if s.cfg.RequestsPerSecond > 0 {
		limiter = newRateLimiter(s.cfg.RequestsPerSecond)
		defer limiter.Stop()
	}

	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = cancelledResult(scanID, req.TargetID, j, ctx.Err())
				return
			}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[i] = cancelledResult(scanID, req.TargetID, j, ctx.Err())
				return
			}

			if scope != nil && !scope.Allowed(j.host) {
				results[i] = PortResult{
					ScanID: scanID, TargetID: req.TargetID, Host: j.host, Port: j.port, Protocol: "tcp",
					Skipped: true, SkippedReason: "host is out of scope", ObservedAt: time.Now().UTC(),
				}
				return
			}

			if limiter != nil {
				select {
				case <-limiter.C:
				case <-ctx.Done():
					results[i] = cancelledResult(scanID, req.TargetID, j, ctx.Err())
					return
				}
			}

			result := s.connect(ctx, scanID, req.TargetID, j.host, j.port)
			results[i] = result
			s.logResult(result)
		}(i, j)
	}
	wg.Wait()

	return summarize(scanID, req.TargetID, req.Target, req.Hosts, results, time.Since(start)), nil
}

type job struct {
	host string
	port int
}

// buildJobs cross-products hosts x ports, deduplicated (phase4.md §39
// "duplicate targets") and in deterministic order.
func buildJobs(hosts []string, ports []int) []job {
	seen := make(map[job]bool)
	var jobs []job
	for _, h := range hosts {
		for _, p := range ports {
			j := job{host: h, port: p}
			if !seen[j] {
				seen[j] = true
				jobs = append(jobs, j)
			}
		}
	}
	return jobs
}

func cancelledResult(scanID, targetID uuid.UUID, j job, err error) PortResult {
	return PortResult{
		ScanID: scanID, TargetID: targetID, Host: j.host, Port: j.port, Protocol: "tcp",
		State: StateError, Error: err.Error(), ObservedAt: time.Now().UTC(),
	}
}

// connect performs one bounded TCP connect attempt and, for an OPEN port,
// conservative port-based classification plus (for HTTPS/TLS_SERVICE
// candidates only) a bounded, metadata-only TLS handshake.
func (s *Scanner) connect(ctx context.Context, scanID, targetID uuid.UUID, host string, port int) PortResult {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()

	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
	defer cancel()

	conn, err := s.dial(dialCtx, "tcp", address)
	duration := time.Since(start)

	result := PortResult{
		ScanID: scanID, TargetID: targetID, Host: host, Port: port, Protocol: "tcp",
		Duration: duration, ObservedAt: time.Now().UTC(),
	}

	if err != nil {
		result.State = classifyDialError(err)
		if result.State == StateError {
			result.Error = err.Error()
		}
		return result
	}
	_ = conn.Close()

	result.State = StateOpen
	service := classifyPort(port)
	result.Service = service
	if indicator := classificationIndicator(port, service); indicator != "" {
		result.Indicators = append(result.Indicators, indicator)
	}

	if httpCandidate(port, s.cfg.HTTPCandidatePorts) {
		result.HTTPCandidate = true
		result.Indicators = append(result.Indicators, "port is configured as an HTTP candidate port — not a confirmed HTTP service")
	}
	if candidate, reason := aiServiceCandidate(port, s.cfg.AICandidatePorts); candidate {
		result.AIServiceCandidate = true
		result.CandidateReason = reason
		result.Indicators = append(result.Indicators, "port is a configured AI-service candidate port — NOT a confirmed AI service")
	}

	if service == ServiceHTTPS || service == ServiceTLS {
		if meta := s.probeTLS(ctx, host, port); meta != nil {
			result.TLSMetadata = meta
			result.Indicators = append(result.Indicators, "TLS handshake succeeded")
		}
	}

	return result
}

// probeTLS attempts a bounded TLS handshake purely to capture safe
// metadata (version, cipher, certificate CommonNames, expiry) — no
// application-layer payload is ever sent (phase4.md §22/§29). A failed
// handshake is not an error; it just means no TLS metadata is available
// for this (still OPEN) port.
func (s *Scanner) probeTLS(ctx context.Context, host string, port int) *TLSMetadata {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
	defer cancel()
	rawConn, err := s.dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		//nolint:gosec // metadata capture only (version/cipher/cert CommonName) — the connection's content is never trusted or used, so certificate validation failures must not prevent observing that TLS is present
		InsecureSkipVerify: true,
	})
	defer func() { _ = tlsConn.Close() }()

	handshakeCtx, cancel2 := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
	defer cancel2()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return nil
	}

	state := tlsConn.ConnectionState()
	meta := &TLSMetadata{
		Version:              tlsVersionName(state.Version),
		CipherSuite:          tls.CipherSuiteName(state.CipherSuite),
		PeerCertificateCount: len(state.PeerCertificates),
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		meta.Subject = cert.Subject.CommonName
		meta.Issuer = cert.Issuer.CommonName
		meta.NotAfter = cert.NotAfter
	}
	return meta
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// classifyDialError distinguishes CLOSED (connection actively refused —
// informative: nothing is listening) from TIMEOUT (the dial deadline or
// context was exceeded — never relabeled FILTERED, since a bare timeout
// cannot establish firewall semantics) from ERROR (anything else: network
// unreachable, DNS failure for a HOST target, unexpected dial failure).
func classifyDialError(err error) State {
	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) && errors.Is(syscallErr.Err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	return StateError
}

func (s *Scanner) logResult(r PortResult) {
	if r.Error != "" {
		s.logger.Warn("network_scan_attempt_failed",
			"scan_id", r.ScanID, "target_id", r.TargetID, "host", r.Host, "port", r.Port,
			"protocol", r.Protocol, "state", r.State, "error", r.Error)
		return
	}
	s.logger.Info("network_scan_attempt_completed",
		"scan_id", r.ScanID, "target_id", r.TargetID, "host", r.Host, "port", r.Port,
		"protocol", r.Protocol, "state", r.State, "duration", r.Duration, "service", r.Service)
}

// summarize aggregates results into the scan summary phase4.md §30
// describes.
func summarize(scanID, targetID uuid.UUID, target string, hosts []string, results []PortResult, duration time.Duration) *Summary {
	summary := &Summary{
		ScanID: scanID, TargetID: targetID, Target: target,
		HostsScanned: len(hosts), PortsAttempted: len(results),
		Duration: duration, Results: results,
	}

	for _, r := range results {
		switch r.State {
		case StateOpen:
			summary.Open++
		case StateClosed:
			summary.Closed++
		case StateTimeout:
			summary.Timeouts++
		case StateError:
			summary.Errors++
		}
		if r.HTTPCandidate {
			summary.HTTPCandidates++
		}
		if r.AIServiceCandidate {
			summary.AICandidates++
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

// rateLimiter paces connection attempts to at most cfg.RequestsPerSecond
// per second in aggregate across every worker goroutine — a safety/
// stability control (phase4.md §18), not stealth timing (phase4.md §50):
// it is a fixed-interval ticker, never randomized.
type rateLimiter struct {
	ticker *time.Ticker
	C      <-chan time.Time
}

func newRateLimiter(requestsPerSecond float64) *rateLimiter {
	interval := time.Duration(float64(time.Second) / requestsPerSecond)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	t := time.NewTicker(interval)
	return &rateLimiter{ticker: t, C: t.C}
}

func (r *rateLimiter) Stop() { r.ticker.Stop() }
