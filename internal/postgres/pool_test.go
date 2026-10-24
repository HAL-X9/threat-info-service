package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

const testDSN = "postgres://user:secret@127.0.0.1:1/threats?sslmode=disable"

func testConfig() config.Database {
	return config.Database{
		DSN: testDSN,
		Pool: config.Pool{
			MinConns:          2,
			MaxConns:          10,
			MaxConnLifetime:   time.Hour,
			MaxConnIdleTime:   15 * time.Minute,
			HealthCheckPeriod: 30 * time.Second,
		},
		Timeouts: config.DatabaseTimeouts{Connect: time.Second},
	}
}

func TestNewPoolConfigAppliesSettings(t *testing.T) {
	got, err := newPoolConfig(testConfig())
	if err != nil {
		t.Fatalf("newPoolConfig: %v", err)
	}

	if got.MinConns != 2 || got.MaxConns != 10 {
		t.Errorf("conns = %d..%d, want 2..10", got.MinConns, got.MaxConns)
	}

	if got.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime = %v, want 1h", got.MaxConnLifetime)
	}

	if got.MaxConnIdleTime != 15*time.Minute {
		t.Errorf("MaxConnIdleTime = %v, want 15m", got.MaxConnIdleTime)
	}

	if got.HealthCheckPeriod != 30*time.Second {
		t.Errorf("HealthCheckPeriod = %v, want 30s", got.HealthCheckPeriod)
	}

	if got.ConnConfig.ConnectTimeout != time.Second {
		t.Errorf("ConnectTimeout = %v, want 1s", got.ConnConfig.ConnectTimeout)
	}
}

func TestNewPoolConfigDoesNotLeakPassword(t *testing.T) {
	cfg := testConfig()
	cfg.DSN = "postgres://user:secret@host:notaport/db"

	_, err := newPoolConfig(cfg)
	if err == nil {
		t.Fatal("newPoolConfig succeeded for a malformed dsn, want an error")
	}

	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestNewPoolFailsWhenDatabaseIsUnreachable(t *testing.T) {
	pool, err := NewPool(context.Background(), testConfig())
	if err == nil {
		pool.Close()
		t.Fatal("NewPool succeeded against a closed port, want an error")
	}
}
