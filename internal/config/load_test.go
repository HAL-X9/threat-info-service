package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDSN = "postgres://user:pass@localhost:5432/threats"

// validYAML is a complete, valid document: the loader has no defaults, so
// every section must be present.
const validYAML = `
log:
  level: debug

httpserver:
  addr: ":8080"
  timeouts:
    read_timeout: 10s
    read_header_timeout: 5s
    write_timeout: 30s
    idle_timeout: 120s
  max_header_bytes: 1048576

  rate_limit:
    requests_per_second: 10
    burst: 20

database:
  pool:
    min_conns: 2
    max_conns: 10
    max_conn_lifetime: 1h
    max_conn_idle_time: 15m
    health_check_period: 30s
  timeouts:
    connect: 5s
    query: 5s
    transaction: 10s
`

func env(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}

func TestLoadValidDocument(t *testing.T) {
	cfg, err := Load(writeConfig(t, validYAML), env(map[string]string{EnvDatabaseDSN: testDSN}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != slog.LevelDebug {
		t.Errorf("Log.Level = %v, want debug", cfg.Log.Level)
	}

	if cfg.HTTPServer.Addr != ":8080" {
		t.Errorf("HTTPServer.Addr = %q, want :8080", cfg.HTTPServer.Addr)
	}

	if cfg.HTTPServer.RateLimit != (RateLimit{RequestsPerSecond: 10, Burst: 20}) {
		t.Errorf("RateLimit = %+v, want 10 requests per second with a burst of 20", cfg.HTTPServer.RateLimit)
	}

	if cfg.HTTPServer.Timeouts.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.HTTPServer.Timeouts.ReadHeaderTimeout)
	}

	if cfg.Database.Pool.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime = %v, want 1h", cfg.Database.Pool.MaxConnLifetime)
	}

	if cfg.Database.Timeouts.Transaction != 10*time.Second {
		t.Errorf("Transaction = %v, want 10s", cfg.Database.Timeouts.Transaction)
	}
}

func TestLoadTakesDSNFromEnvironment(t *testing.T) {
	cfg, err := Load(writeConfig(t, validYAML), env(map[string]string{EnvDatabaseDSN: testDSN}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Database.DSN != testDSN {
		t.Errorf("DSN = %q, want the value of %s", cfg.Database.DSN, EnvDatabaseDSN)
	}
}

func TestLoadRequiresDSN(t *testing.T) {
	_, err := Load(writeConfig(t, validYAML), env(nil))
	if err == nil {
		t.Fatal("Load succeeded without a DSN, want an error")
	}

	if !strings.Contains(err.Error(), "dsn") {
		t.Errorf("error = %v, want it to mention dsn", err)
	}
}

func TestLoadRejectsDSNInYAML(t *testing.T) {
	doc := strings.Replace(validYAML, "database:\n", "database:\n  dsn: "+testDSN+"\n", 1)

	_, err := Load(writeConfig(t, doc), env(map[string]string{EnvDatabaseDSN: testDSN}))
	if err == nil {
		t.Fatal("Load accepted a dsn key in YAML, want an error: secrets belong in the environment")
	}
}

func TestLoadRejectsBadDocuments(t *testing.T) {
	tests := map[string]string{
		"unknown key":          validYAML + "\nunknown: 1\n",
		"unknown nested key":   strings.Replace(validYAML, "addr:", "adrr:", 1),
		"malformed duration":   strings.Replace(validYAML, "read_timeout: 10s", "read_timeout: soon", 1),
		"unknown log level":    strings.Replace(validYAML, "level: debug", "level: verbose", 1),
		"zero rate limit":      strings.Replace(validYAML, "requests_per_second: 10", "requests_per_second: 0", 1),
		"wrong type":           strings.Replace(validYAML, "max_header_bytes: 1048576", "max_header_bytes: lots", 1),
		"invalid yaml":         "httpserver: [",
		"empty file":           "",
		"semantically invalid": strings.Replace(validYAML, "max_conns: 10", "max_conns: 1", 1),
	}

	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, doc), env(map[string]string{EnvDatabaseDSN: testDSN}))
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	_, err := Load(path, env(map[string]string{EnvDatabaseDSN: testDSN}))
	if err == nil {
		t.Fatal("Load succeeded for a missing file, want an error")
	}

	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the path", err)
	}
}

func TestResolvePath(t *testing.T) {
	tests := map[string]struct {
		flag string
		env  map[string]string
		want string
	}{
		"default": {
			want: DefaultConfigPath,
		},
		"environment beats default": {
			env:  map[string]string{EnvConfigPath: "/etc/env.yaml"},
			want: "/etc/env.yaml",
		},
		"flag beats environment": {
			flag: "/etc/flag.yaml",
			env:  map[string]string{EnvConfigPath: "/etc/env.yaml"},
			want: "/etc/flag.yaml",
		},
		"empty environment value falls back to default": {
			env:  map[string]string{EnvConfigPath: ""},
			want: DefaultConfigPath,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ResolvePath(tc.flag, env(tc.env)); got != tc.want {
				t.Errorf("ResolvePath = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShippedConfigIsValid guards the example config that ships with the
// repository: it must always load once the secrets are provided.
func TestShippedConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", DefaultConfigPath)

	if _, err := Load(path, env(map[string]string{EnvDatabaseDSN: testDSN})); err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
}
