package ai

import (
	"sync"
	"time"
)

// RateLimitConfig bounds how many AI requests one user, or one target
// overall, may start within a rolling window (phase13.md §55/§112):
// "prevent one user from exhausting project AI quota". This platform has
// no shared cache/queue infrastructure yet (Redis is verified at startup
// but not otherwise used — see cmd/worker's own doc comment), so this is
// a documented, process-local limiter, not a cluster-wide one — the same
// adaptation Phase 12 already applied to its own "worker pool" section.
type RateLimitConfig struct {
	PerUserPerMinute   int
	PerTargetPerMinute int
	MaxConcurrent      int
}

// Effective returns c with every zero field replaced by its default —
// generous enough not to interfere with normal analyst use, but never
// unbounded.
func (c RateLimitConfig) Effective() RateLimitConfig {
	if c.PerUserPerMinute <= 0 {
		c.PerUserPerMinute = 20
	}
	if c.PerTargetPerMinute <= 0 {
		c.PerTargetPerMinute = 60
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 4
	}
	return c
}

// rateLimiter is a simple, deterministic sliding-window counter — no
// external dependency, safe for concurrent use.
type rateLimiter struct {
	cfg RateLimitConfig

	mu       sync.Mutex
	byUser   map[string][]time.Time
	byTarget map[string][]time.Time
	inFlight int
}

func newRateLimiter(cfg RateLimitConfig) *rateLimiter {
	return &rateLimiter{cfg: cfg.Effective(), byUser: map[string][]time.Time{}, byTarget: map[string][]time.Time{}}
}

// Allow reports whether a new request for (userID, targetID) may start
// right now, and if so, reserves a concurrency slot — the caller must
// call Release when the request finishes, success or failure.
func (l *rateLimiter) Allow(userID, targetID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	l.byUser[userID] = prune(l.byUser[userID], cutoff)
	l.byTarget[targetID] = prune(l.byTarget[targetID], cutoff)

	if l.inFlight >= l.cfg.MaxConcurrent {
		return false
	}
	if len(l.byUser[userID]) >= l.cfg.PerUserPerMinute {
		return false
	}
	if len(l.byTarget[targetID]) >= l.cfg.PerTargetPerMinute {
		return false
	}

	l.byUser[userID] = append(l.byUser[userID], now)
	l.byTarget[targetID] = append(l.byTarget[targetID], now)
	l.inFlight++
	return true
}

// Release frees the concurrency slot reserved by a successful Allow.
func (l *rateLimiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight > 0 {
		l.inFlight--
	}
}

func prune(times []time.Time, cutoff time.Time) []time.Time {
	out := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}
