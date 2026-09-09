package analytics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	analyticsrepo "ai-surface-platform/internal/repository/analytics"
)

// Filters narrows an analytics query — only fields this platform's data
// model actually supports are exposed (phase14.md §22: "only expose
// filters supported by the existing data model"). Every result method
// below documents which of these it actually honors; not every metric
// can meaningfully apply every filter (e.g. a target-wide asset count
// has no "detection" filter to apply).
type Filters struct {
	Severity string
	Status   string
}

// hash returns a short, deterministic fingerprint of f for use in a
// cache key (phase14.md §59) — never used for anything security-
// sensitive, only cache-key uniqueness.
func (f Filters) hash() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", f.Severity, f.Status)))
	return hex.EncodeToString(sum[:])[:12]
}

// Service is the dashboard-facing analytics API — the only layer a CLI
// command or (a future) API handler should call.
type Service struct {
	repo  analyticsrepo.Repository
	cache *Cache
}

// NewService builds a Service. cache may be nil, in which case a
// DefaultCacheTTL cache is created.
func NewService(repo analyticsrepo.Repository, cache *Cache) *Service {
	if cache == nil {
		cache = NewCache(DefaultCacheTTL)
	}
	return &Service{repo: repo, cache: cache}
}

// cached memoizes compute() under a key built from every component
// phase14.md §59 requires — target, metric, range, and filters — so a
// cache hit can never leak across a target boundary.
func cached[T any](s *Service, targetID uuid.UUID, metric string, r TimeRange, f Filters, compute func() (T, error)) (T, error) {
	key := CacheKey(targetID, metric, r, f.hash())
	if v, ok := s.cache.Get(key); ok {
		if typed, ok := v.(T); ok {
			return typed, nil
		}
	}
	result, err := compute()
	if err != nil {
		var zero T
		return zero, err
	}
	s.cache.Set(key, result)
	return result, nil
}
