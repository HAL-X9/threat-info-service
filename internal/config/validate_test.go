package config

import (
	"strings"
	"testing"
	"time"
)

// validConfig returns a configuration that passes Validate. Each test case
// breaks exactly one thing in it.
func validConfig() *Config {
	return &Config{
		APIToken: testToken,
		HTTPServer: HTTPServer{
			Addr: ":8080",
			Timeouts: HTTPTimeouts{
				ReadTimeout:       10 * time.Second,
				ReadHeaderTimeout: 5 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       2 * time.Minute,
			},
			MaxHeaderBytes: 1 << 20,
			MaxBodyBytes:   1 << 16,
			RateLimit:      RateLimit{RequestsPerSecond: 10, Burst: 20},
		},
		Database: Database{
			DSN: testDSN,
			Pool: Pool{
				MinConns:          2,
				MaxConns:          10,
				MaxConnLifetime:   time.Hour,
				MaxConnIdleTime:   15 * time.Minute,
				HealthCheckPeriod: 30 * time.Second,
			},
			Timeouts: DatabaseTimeouts{
				Connect:     5 * time.Second,
				Query:       5 * time.Second,
				Transaction: 10 * time.Second,
			},
		},
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := Validate(validConfig()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateAcceptsBoundaryValues(t *testing.T) {
	tests := map[string]func(*Config){
		"zero max_header_bytes uses the net/http default": func(c *Config) { c.HTTPServer.MaxHeaderBytes = 0 },
		"fractional rate": func(c *Config) { c.HTTPServer.RateLimit.RequestsPerSecond = 0.5 },
		"burst of one":    func(c *Config) { c.HTTPServer.RateLimit.Burst = 1 },
		"read_header_timeout equals read_timeout": func(c *Config) {
			c.HTTPServer.Timeouts.ReadHeaderTimeout = c.HTTPServer.Timeouts.ReadTimeout
		},
		"min_conns zero":                func(c *Config) { c.Database.Pool.MinConns = 0 },
		"min_conns equals max_conns":    func(c *Config) { c.Database.Pool.MinConns = c.Database.Pool.MaxConns },
		"idle time equals lifetime":     func(c *Config) { c.Database.Pool.MaxConnIdleTime = c.Database.Pool.MaxConnLifetime },
		"transaction equals query":      func(c *Config) { c.Database.Timeouts.Transaction = c.Database.Timeouts.Query },
		"host and port without address": func(c *Config) { c.HTTPServer.Addr = "127.0.0.1:9000" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(cfg)

			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestValidateRejectsInvalidConfig(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"empty addr": {
			mutate:  func(c *Config) { c.HTTPServer.Addr = "" },
			wantErr: "addr",
		},
		"addr without port": {
			mutate:  func(c *Config) { c.HTTPServer.Addr = "localhost" },
			wantErr: "invalid addr",
		},
		"negative max_header_bytes": {
			mutate:  func(c *Config) { c.HTTPServer.MaxHeaderBytes = -1 },
			wantErr: "max_header_bytes",
		},
		"no api token": {
			mutate:  func(c *Config) { c.APIToken = "" },
			wantErr: "token",
		},
		"zero max_body_bytes": {
			mutate:  func(c *Config) { c.HTTPServer.MaxBodyBytes = 0 },
			wantErr: "max_body_bytes",
		},
		"negative max_body_bytes": {
			mutate:  func(c *Config) { c.HTTPServer.MaxBodyBytes = -1 },
			wantErr: "max_body_bytes",
		},
		"zero requests_per_second": {
			mutate:  func(c *Config) { c.HTTPServer.RateLimit.RequestsPerSecond = 0 },
			wantErr: "requests_per_second",
		},
		"negative requests_per_second": {
			mutate:  func(c *Config) { c.HTTPServer.RateLimit.RequestsPerSecond = -1 },
			wantErr: "requests_per_second",
		},
		"zero burst": {
			mutate:  func(c *Config) { c.HTTPServer.RateLimit.Burst = 0 },
			wantErr: "burst",
		},
		"zero read_timeout": {
			mutate:  func(c *Config) { c.HTTPServer.Timeouts.ReadTimeout = 0 },
			wantErr: "read_timeout",
		},
		"zero read_header_timeout": {
			mutate:  func(c *Config) { c.HTTPServer.Timeouts.ReadHeaderTimeout = 0 },
			wantErr: "read_header_timeout",
		},
		"read_header_timeout above read_timeout": {
			mutate:  func(c *Config) { c.HTTPServer.Timeouts.ReadHeaderTimeout = time.Minute },
			wantErr: "read_header_timeout cannot exceed",
		},
		"negative write_timeout": {
			mutate:  func(c *Config) { c.HTTPServer.Timeouts.WriteTimeout = -time.Second },
			wantErr: "write_timeout",
		},
		"zero idle_timeout": {
			mutate:  func(c *Config) { c.HTTPServer.Timeouts.IdleTimeout = 0 },
			wantErr: "idle_timeout",
		},
		"empty dsn": {
			mutate:  func(c *Config) { c.Database.DSN = "" },
			wantErr: "dsn",
		},
		"negative min_conns": {
			mutate:  func(c *Config) { c.Database.Pool.MinConns = -1 },
			wantErr: "min_conns cannot be negative",
		},
		"zero max_conns": {
			mutate:  func(c *Config) { c.Database.Pool.MaxConns = 0 },
			wantErr: "max_conns must be greater",
		},
		"min_conns above max_conns": {
			mutate:  func(c *Config) { c.Database.Pool.MinConns = 11 },
			wantErr: "min_conns cannot exceed",
		},
		"zero max_conn_lifetime": {
			mutate:  func(c *Config) { c.Database.Pool.MaxConnLifetime = 0 },
			wantErr: "max_conn_lifetime",
		},
		"zero max_conn_idle_time": {
			mutate:  func(c *Config) { c.Database.Pool.MaxConnIdleTime = 0 },
			wantErr: "max_conn_idle_time",
		},
		"zero health_check_period": {
			mutate:  func(c *Config) { c.Database.Pool.HealthCheckPeriod = 0 },
			wantErr: "health_check_period",
		},
		"idle time above lifetime": {
			mutate:  func(c *Config) { c.Database.Pool.MaxConnIdleTime = 2 * time.Hour },
			wantErr: "max_conn_idle_time cannot exceed",
		},
		"zero connect timeout": {
			mutate:  func(c *Config) { c.Database.Timeouts.Connect = 0 },
			wantErr: "connect",
		},
		"zero query timeout": {
			mutate:  func(c *Config) { c.Database.Timeouts.Query = 0 },
			wantErr: "query",
		},
		"zero transaction timeout": {
			mutate:  func(c *Config) { c.Database.Timeouts.Transaction = 0 },
			wantErr: "transaction",
		},
		"transaction below query": {
			mutate:  func(c *Config) { c.Database.Timeouts.Transaction = time.Second },
			wantErr: "transaction timeout cannot be less",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)

			err := Validate(cfg)
			if err == nil {
				t.Fatal("Validate succeeded, want an error")
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateRejectsNilConfig(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Fatal("Validate(nil) succeeded, want an error")
	}
}
