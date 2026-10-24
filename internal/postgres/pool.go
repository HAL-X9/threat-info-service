package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

// NewPool opens a connection pool and pings the database, so a wrong DSN or an
// unreachable database fails at startup. The caller must Close the pool.
func NewPool(ctx context.Context, cfg config.Database) (*pgxpool.Pool, error) {
	poolCfg, err := newPoolConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeouts.Connect)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err = pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}

func newPoolConfig(cfg config.Database) (*pgxpool.Config, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}

	poolCfg.MinConns = int32(cfg.Pool.MinConns)
	poolCfg.MaxConns = int32(cfg.Pool.MaxConns)
	poolCfg.MaxConnLifetime = cfg.Pool.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.Pool.MaxConnIdleTime
	poolCfg.HealthCheckPeriod = cfg.Pool.HealthCheckPeriod
	poolCfg.ConnConfig.ConnectTimeout = cfg.Timeouts.Connect

	return poolCfg, nil
}
