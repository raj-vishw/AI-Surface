package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"ai-recon-platform/internal/intelligence"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
)

// postgresCache adapts intelrepo.CacheRepository (raw bytes) into
// internal/intelligence.Cache (typed Records) — the one place this
// package crosses the engine/repository boundary for caching, so
// internal/repository/intelligence itself never needs to import the
// engine package (see that package's doc comment).
type postgresCache struct {
	repo intelrepo.CacheRepository
}

func newPostgresCache(repo intelrepo.CacheRepository) *postgresCache {
	return &postgresCache{repo: repo}
}

var _ intelligence.Cache = (*postgresCache)(nil)

func (c *postgresCache) Get(ctx context.Context, key intelligence.CacheKey) ([]intelligence.Record, bool, error) {
	data, expiresAt, found, err := c.repo.GetCacheEntry(ctx, key.ProviderID, string(key.Indicator.Type), key.Indicator.Value)
	if err != nil || !found {
		return nil, false, err
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		return nil, false, nil
	}
	var records []intelligence.Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, false, fmt.Errorf("decoding cached records: %w", err)
	}
	return records, true, nil
}

func (c *postgresCache) Set(ctx context.Context, key intelligence.CacheKey, records []intelligence.Record, ttl time.Duration) error {
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("encoding records for cache: %w", err)
	}
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}
	return c.repo.SetCacheEntry(ctx, key.ProviderID, string(key.Indicator.Type), key.Indicator.Value, data, expiresAt)
}

func (c *postgresCache) Invalidate(ctx context.Context, key intelligence.CacheKey) error {
	return c.repo.InvalidateCacheEntry(ctx, key.ProviderID, string(key.Indicator.Type), key.Indicator.Value)
}
