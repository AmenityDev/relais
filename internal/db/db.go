// Package db owns the Postgres connection pool and the migration runner.
//
// A single DSN is used and no assumption is made about the topology, so a
// Patroni cluster behind HAProxy, a pgbouncer, or a plain single node all work
// unchanged.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amenitydev/relais/internal/config"
)

// Pool is the shared connection pool. It is safe for concurrent use.
type Pool = pgxpool.Pool

// Open builds and verifies the connection pool.
//
// It pings before returning: a service that cannot reach its database should
// fail at startup rather than accept traffic and reject every request.
func Open(ctx context.Context, cfg *config.Config) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	poolCfg.MaxConns = cfg.Database.MaxConns
	poolCfg.MinConns = cfg.Database.MinConns
	poolCfg.MaxConnLifetime = cfg.Database.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.Database.MaxConnIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.Database.ConnectTimeout

	switch cfg.Database.StatementCacheMode {
	case "describe":
		poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	case "none":
		poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	default:
		poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
	}

	// application_name makes a stuck connection identifiable in pg_stat_activity
	// without having to correlate ports.
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if _, set := poolCfg.ConnConfig.RuntimeParams["application_name"]; !set {
		poolCfg.ConnConfig.RuntimeParams["application_name"] = cfg.ServiceName
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.Database.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Healthy reports whether the pool can still serve queries. It is used by the
// readiness probe and deliberately uses a short timeout: a readiness check that
// hangs is worse than one that fails.
func Healthy(ctx context.Context, pool *Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pool.Ping(ctx)
}
