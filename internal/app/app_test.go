package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

var shippedConfig = filepath.Join("..", "..", config.DefaultConfigPath)

func env(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestNewLoadsTheShippedConfig(t *testing.T) {
	getenv := env(map[string]string{config.EnvDatabaseDSN: "postgres://user:pass@localhost:5432/threats", config.EnvAPIToken: "local-test-token-12345"})

	if _, err := New([]string{"-config", shippedConfig}, getenv, io.Discard); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewLogsTheLoadedConfiguration(t *testing.T) {
	var out bytes.Buffer

	getenv := env(map[string]string{config.EnvDatabaseDSN: "postgres://user:pass@localhost:5432/threats", config.EnvAPIToken: "local-test-token-12345"})

	if _, err := New([]string{"-config", shippedConfig}, getenv, &out); err != nil {
		t.Fatalf("New: %v", err)
	}

	var rec map[string]any
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, out.String())
	}

	if rec["msg"] != "configuration loaded" {
		t.Errorf("msg = %v, want %q", rec["msg"], "configuration loaded")
	}

	if rec["path"] != shippedConfig {
		t.Errorf("path = %v, want %q", rec["path"], shippedConfig)
	}

	if strings.Contains(out.String(), "user:pass") {
		t.Errorf("log leaks the DSN: %q", out.String())
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	tests := map[string]struct {
		args []string
		env  map[string]string
	}{
		"missing config file": {
			args: []string{"-config", filepath.Join(t.TempDir(), "missing.yaml")},
			env:  map[string]string{config.EnvDatabaseDSN: "postgres://localhost/threats", config.EnvAPIToken: "local-test-token-12345"},
		},
		"missing dsn": {
			args: []string{"-config", shippedConfig},
		},
		"unknown flag": {
			args: []string{"-nope"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(tc.args, env(tc.env), io.Discard); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}

func TestRunFailsWhenDatabaseIsUnreachable(t *testing.T) {
	getenv := env(map[string]string{
		config.EnvDatabaseDSN: "postgres://user:pass@127.0.0.1:1/threats?sslmode=disable",
		config.EnvAPIToken:    "local-test-token-12345",
	})

	a, err := New([]string{"-config", shippedConfig}, getenv, io.Discard)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = a.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "postgres") {
		t.Fatalf("Run = %v, want an error naming postgres", err)
	}
}
