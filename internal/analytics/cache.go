package analytics

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CacheKey builds a cache key that always embeds target, metric, time
// range, and a filters fingerprint — the four components phase14.md §59
// requires, so cached data can never cross a target boundary: two
// different targets requesting the identical metric/range/filters always
// get different keys.
func CacheKey(targetID uuid.UUID, metric string, r TimeRange, filtersHash string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", targetID, metric, r.Start.UTC().Format(time.RFC3339), r.End.UTC().Format(time.RFC3339), r.Interval, filtersHash)
}

type cacheEntry struct {
	value   any
	expires time.Time
}

// Cache is a bounded-TTL, in-process cache (phase14.md §58/§59/§60) —
// this platform has no shared cache infrastructure in active use (Redis
// is verified at startup only — see cmd/worker's own doc comment), so
// this is a documented, process-local cache, the same adaptation
// internal/service/ai's own rate limiter already applies for the
// identical reason. Never authoritative: a cache miss always falls
// through to a real query, so a restarted process never serves stale or
// missing data.
type Cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

// DefaultCacheTTL bounds how long one aggregate is ever served without
// being recomputed (phase14.md §60: "use bounded TTLs").
const DefaultCacheTTL = 30 * time.Second

// NewCache returns a Cache with the given TTL (DefaultCacheTTL if <= 0).
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{ttl: ttl, m: make(map[string]cacheEntry)}
}

// Get returns the cached value for key, if present and not expired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.m[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.value, true
}

// Set stores value under key with this Cache's configured TTL.
func (c *Cache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{value: value, expires: time.Now().Add(c.ttl)}
}

// Len reports how many entries are currently stored, expired or not —
// exposed for tests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
