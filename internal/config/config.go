package config

import (
	"log/slog"
	"time"
)

type HTTPServer struct {
	Addr           string       `yaml:"addr"`
	Timeouts       HTTPTimeouts `yaml:"timeouts"`
	MaxHeaderBytes int          `yaml:"max_header_bytes"`
	RateLimit      RateLimit    `yaml:"rate_limit"`
}

type RateLimit struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type HTTPTimeouts struct {
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
}

type Database struct {
	DSN      string           `yaml:"-"`
	Pool     Pool             `yaml:"pool"`
	Timeouts DatabaseTimeouts `yaml:"timeouts"`
}

type Pool struct {
	MinConns          int           `yaml:"min_conns"`
	MaxConns          int           `yaml:"max_conns"`
	MaxConnLifetime   time.Duration `yaml:"max_conn_lifetime"`
	MaxConnIdleTime   time.Duration `yaml:"max_conn_idle_time"`
	HealthCheckPeriod time.Duration `yaml:"health_check_period"`
}

type DatabaseTimeouts struct {
	Connect     time.Duration `yaml:"connect"`
	Query       time.Duration `yaml:"query"`
	Transaction time.Duration `yaml:"transaction"`
}

type Log struct {
	Level slog.Level `yaml:"level"`
}

type Config struct {
	Log        Log        `yaml:"log"`
	HTTPServer HTTPServer `yaml:"httpserver"`
	Database   Database   `yaml:"database"`
}
