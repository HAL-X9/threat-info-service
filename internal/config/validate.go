package config

import (
	"fmt"
	"net"
)

// Validate checks the configuration for invalid or inconsistent values.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("validate config: config is nil")
	}

	if err := validateHTTPServer(&cfg.HTTPServer); err != nil {
		return fmt.Errorf("validate httpserver: %w", err)
	}

	if err := validateDatabase(&cfg.Database); err != nil {
		return fmt.Errorf("validate database: %w", err)
	}

	return nil
}

// validateHTTPServer validates HTTP server configuration.
func validateHTTPServer(cfg *HTTPServer) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if cfg.Addr == "" {
		return fmt.Errorf("addr cannot be empty")
	}

	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return fmt.Errorf("invalid addr %q: %w", cfg.Addr, err)
	}

	if err := validateHTTPTimeouts(&cfg.Timeouts); err != nil {
		return fmt.Errorf("invalid timeouts: %w", err)
	}

	if cfg.MaxHeaderBytes < 0 {
		return fmt.Errorf("max_header_bytes cannot be negative")
	}

	if cfg.MaxBodyBytes <= 0 {
		return fmt.Errorf("max_body_bytes must be greater than 0")
	}

	if err := validateRateLimit(&cfg.RateLimit); err != nil {
		return fmt.Errorf("invalid rate_limit: %w", err)
	}

	return nil
}

// validateRateLimit validates the per-client request rate limit.
func validateRateLimit(cfg *RateLimit) error {
	if cfg.RequestsPerSecond <= 0 {
		return fmt.Errorf("requests_per_second must be greater than 0")
	}

	if cfg.Burst < 1 {
		return fmt.Errorf("burst must be at least 1")
	}

	return nil
}

// validateHTTPTimeouts validates HTTP server timeout configuration.
func validateHTTPTimeouts(cfg *HTTPTimeouts) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("read_timeout must be greater than 0")
	}

	if cfg.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("read_header_timeout must be greater than 0")
	}

	if cfg.ReadHeaderTimeout > cfg.ReadTimeout {
		return fmt.Errorf(
			"read_header_timeout cannot exceed read_timeout",
		)
	}

	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("write_timeout must be greater than 0")
	}

	if cfg.IdleTimeout <= 0 {
		return fmt.Errorf("idle_timeout must be greater than 0")
	}

	return nil
}

// validateDatabase validates database configuration.
func validateDatabase(cfg *Database) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if cfg.DSN == "" {
		return fmt.Errorf("dsn cannot be empty")
	}

	if err := validatePool(&cfg.Pool); err != nil {
		return fmt.Errorf("invalid pool: %w", err)
	}

	if err := validateDatabaseTimeouts(&cfg.Timeouts); err != nil {
		return fmt.Errorf("invalid timeouts: %w", err)
	}

	return nil
}

// validatePool validates database connection pool configuration.
func validatePool(cfg *Pool) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if cfg.MinConns < 0 {
		return fmt.Errorf("min_conns cannot be negative")
	}

	if cfg.MaxConns <= 0 {
		return fmt.Errorf("max_conns must be greater than 0")
	}

	if cfg.MinConns > cfg.MaxConns {
		return fmt.Errorf("min_conns cannot exceed max_conns")
	}

	if cfg.MaxConnLifetime <= 0 {
		return fmt.Errorf("max_conn_lifetime must be greater than 0")
	}

	if cfg.MaxConnIdleTime <= 0 {
		return fmt.Errorf("max_conn_idle_time must be greater than 0")
	}

	if cfg.HealthCheckPeriod <= 0 {
		return fmt.Errorf("health_check_period must be greater than 0")
	}

	if cfg.MaxConnIdleTime > cfg.MaxConnLifetime {
		return fmt.Errorf(
			"max_conn_idle_time cannot exceed max_conn_lifetime",
		)
	}

	return nil
}

// validateDatabaseTimeouts validates database timeout configuration.
func validateDatabaseTimeouts(cfg *DatabaseTimeouts) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if cfg.Connect <= 0 {
		return fmt.Errorf("connect must be greater than 0")
	}

	if cfg.Query <= 0 {
		return fmt.Errorf("query must be greater than 0")
	}

	if cfg.Transaction <= 0 {
		return fmt.Errorf("transaction must be greater than 0")
	}

	if cfg.Transaction < cfg.Query {
		return fmt.Errorf(
			"transaction timeout cannot be less than query timeout",
		)
	}

	return nil
}
