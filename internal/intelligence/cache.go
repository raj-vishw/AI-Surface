package intelligence

import (
	"context"
	"sync"
	"time"
)

// CacheKey identifies one cached provider lookup — provider, indicator
// type, and normalized indicator value (phase10.md §23).
type CacheKey struct {
	ProviderID string
	Indicator  Indicator
}

// Cache stores provider lookup results so external services aren't
// queried unnecessarily (phase10.md §23). Implementations must respect
// per-entry TTL (Set's ttl argument) and treat an expired entry as a
// miss. The engine depends only on this interface — a persistent
// (Postgres-backed) implementation lives in internal/repository/
// intelligence and is injected by internal/service/intelligence, keeping
// this package free of any database dependency (phase10.md §1).
type Cache interface {
	Get(ctx context.Context, key CacheKey) ([]Record, bool, error)
	Set(ctx context.Context, key CacheKey, records []Record, ttl time.Duration) error
	// Invalidate removes key's entry regardless of TTL — used by manual/
	// provider refresh (phase10.md §24).
	Invalidate(ctx context.Context, key CacheKey) error
}

type memoryCacheEntry struct {
	records   []Record
	expiresAt time.Time
}

// MemoryCache is an in-process Cache implementation — the default when
// no persistent cache is wired (tests, and any deployment that hasn't
// configured one). Entries do not survive a process restart.
type MemoryCache struct {
	mu      sync.Mutex
	entries map[CacheKey]memoryCacheEntry
}

// NewMemoryCache builds an empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: map[CacheKey]memoryCacheEntry{}}
}

// Get implements Cache.
func (c *MemoryCache) Get(_ context.Context, key CacheKey) ([]Record, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false, nil
	}
	return entry.records, true, nil
}

// Set implements Cache. ttl <= 0 means "never expires".
func (c *MemoryCache) Set(_ context.Context, key CacheKey, records []Record, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}
	c.entries[key] = memoryCacheEntry{records: records, expiresAt: expiresAt}
	return nil
}

// Invalidate implements Cache.
func (c *MemoryCache) Invalidate(_ context.Context, key CacheKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	return nil
}
