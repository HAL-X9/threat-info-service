package app

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	defer func() { _ = ln.Close() }()

	return ln.Addr().String()
}

// newApp builds an App from the shipped config, listening on addr.
func newApp(t *testing.T, addr string) *App {
	t.Helper()

	src, err := os.ReadFile(filepath.Join("..", "..", config.DefaultConfigPath))
	if err != nil {
		t.Fatalf("read shipped config: %v", err)
	}

	doc := strings.Replace(string(src), `":8080"`, `"`+addr+`"`, 1)
	if doc == string(src) {
		t.Fatal("shipped config has no :8080 address to replace")
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	getenv := func(key string) string {
		if key == config.EnvDatabaseDSN {
			return "postgres://user:pass@localhost:5432/threats"
		}

		return ""
	}

	a, err := New([]string{"-config", path}, getenv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return a
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunServesAndStopsOnCancel(t *testing.T) {
	addr := freeAddr(t)
	a := newApp(t, addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	waitUntil(t, "/healthz to answer 200", func() bool {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	})

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil after a requested shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s")
	}

	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Error("the server still accepts connections after Run returned")
	}
}

func TestRunFailsWhenAddressIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy address: %v", err)
	}
	defer func() { _ = taken.Close() }()

	a := newApp(t, taken.Addr().String())

	if err = a.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded although the address was taken, want an error")
	}
}

func TestNewFailsOnMissingConfig(t *testing.T) {
	_, err := New([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")}, func(string) string { return "" })
	if err == nil {
		t.Fatal("New succeeded with a missing config, want an error")
	}
}

func TestHandlerRoutes(t *testing.T) {
	tests := map[string]struct {
		method string
		path   string
		want   int
	}{
		"healthz":        {http.MethodGet, "/healthz", http.StatusOK},
		"healthz head":   {http.MethodHead, "/healthz", http.StatusOK},
		"healthz method": {http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		"unknown path":   {http.MethodGet, "/nope", http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			newHandler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}
