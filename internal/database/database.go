// Package database provides the platform's PostgreSQL connection pool.
//
// This is infrastructure only: it opens connections, validates
// configuration, pings PostgreSQL, exposes pooling, and reports health. It
// does not implement application repositories — those are added when a
// concrete schema exists.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"ai-recon-platform/internal/config"
	apperrors "ai-recon-platform/internal/errors"
)

// Pool wraps a pgxpool.Pool so the rest of the codebase depends on this
// package rather than directly on pgx, keeping the driver swappable.
type Pool struct {
	*pgxpool.Pool
}

// Connect establishes a connection pool to PostgreSQL and verifies
// connectivity with a ping before returning. It never returns a Pool that
// hasn't been confirmed reachable.
//
// Pool sizing maps from config.DatabaseConfig onto pgxpool's model:
// MaxOpenConnections -> MaxConns, MaxIdleConnections -> MinConns (pgxpool
// has no separate idle cap; MinConns is the closest equivalent, the number
// of connections kept warm), ConnMaxLifetime -> MaxConnLifetime,
// ConnMaxIdleTime -> MaxConnIdleTime.
//
// A zero ConnMaxLifetime/ConnMaxIdleTime means "use pgxpool's built-in
// default," matching the database/sql convention of 0 meaning "no limit."
// This must not be applied unconditionally: pgxpool interprets an
// explicit zero MaxConnLifetime as "already expired," which causes every
// connection to be torn down and recreated immediately — the opposite of
// what a caller leaving the field unset would expect.
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, apperrors.NewConfiguration("parsing database DSN", err)
	}
	poolCfg.MaxConns = cfg.MaxOpenConnections
	poolCfg.MinConns = cfg.MaxIdleConnections
	if cfg.ConnMaxLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	}
	if cfg.ConnMaxIdleTime > 0 {
		poolCfg.MaxConnIdleTime = cfg.ConnMaxIdleTime
	}

	connectCtx, cancelConnect := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancelConnect()

	pool, err := pgxpool.NewWithConfig(connectCtx, poolCfg)
	if err != nil {
		return nil, apperrors.NewDatabase("creating database pool", err)
	}

	pingCtx, cancelPing := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, apperrors.NewDatabase("pinging database", err)
	}

	return &Pool{Pool: pool}, nil
}

// HealthCheck pings the database within ctx. It is intended for use by the
// server's /ready endpoint.
func (p *Pool) HealthCheck(ctx context.Context) error {
	if p == nil || p.Pool == nil {
		return fmt.Errorf("database pool not initialized")
	}
	return p.Ping(ctx)
}
