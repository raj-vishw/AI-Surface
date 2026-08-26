// Package redis provides the platform's Redis client.
//
// For Phase 1 this is infrastructure only — connect, ping, health-check,
// close. Job queues, scheduling, distributed locks, and rate limiting are
// built on top of this in later phases.
package redis

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"

	"ai-recon-platform/internal/config"
	apperrors "ai-recon-platform/internal/errors"
)

// Client wraps a *goredis.Client so the rest of the codebase depends on
// this package rather than directly on go-redis, keeping the driver
// swappable.
type Client struct {
	*goredis.Client
}

// Connect builds a Redis client and verifies connectivity with a ping
// before returning. It never returns a Client that hasn't been confirmed
// reachable.
func Connect(ctx context.Context, cfg config.RedisConfig) (*Client, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.Database,
	})

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, apperrors.NewNetwork("pinging redis", err)
	}

	return &Client{Client: client}, nil
}

// HealthCheck pings Redis within ctx. It is intended for use by the
// server's /ready endpoint.
func (c *Client) HealthCheck(ctx context.Context) error {
	if c == nil || c.Client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	return c.Client.Ping(ctx).Err()
}
