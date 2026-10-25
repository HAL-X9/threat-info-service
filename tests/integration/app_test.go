//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/HAL-X9/threat-info-service/internal/app"
	"github.com/HAL-X9/threat-info-service/internal/config"
)

const (
	postgresImage = "postgres:18-alpine"
	database      = "threats"
)

type service struct {
	addr string
	logs *bytes.Buffer
	stop func() error
}

func startPostgres(t *testing.T) (*tcpostgres.PostgresContainer, string) {
	t.Helper()

	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctr, err := tcpostgres.Run(t.Context(), postgresImage,
		tcpostgres.WithDatabase(database),
		tcpostgres.WithUsername("threats"),
		tcpostgres.WithPassword("threats"),
		tcpostgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, ctr)

	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}

	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	return ctr, dsn
}

// startService runs the whole application against dsn, on a free port. The
// service is stopped when the test ends, if the test has not stopped it already.
func startService(t *testing.T, dsn string) *service {
	t.Helper()

	addr := freeAddr(t)

	src, err := os.ReadFile(filepath.Join("..", "..", config.DefaultConfigPath))
	if err != nil {
		t.Fatalf("read shipped config: %v", err)
	}

	doc := strings.NewReplacer(
		`":8080"`, `"`+addr+`"`,
		"requests_per_second: 10", "requests_per_second: 1000",
		"burst: 20", "burst: 1000",
	).Replace(string(src))
	if !strings.Contains(doc, addr) || !strings.Contains(doc, "burst: 1000") {
		t.Fatal("shipped config lacks the address or the rate limit to override")
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	getenv := func(key string) string {
		if key == config.EnvDatabaseDSN {
			return dsn
		}

		return ""
	}

	logs := new(bytes.Buffer)

	a, err := app.New([]string{"-config", path}, getenv, logs)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- a.Run(ctx) }()

	var (
		once    sync.Once
		stopErr error
	)

	stop := func() error {
		once.Do(func() {
			cancel()
			stopErr = <-done
		})

		return stopErr
	}
	t.Cleanup(func() { _ = stop() })

	return &service{addr: addr, logs: logs, stop: stop}
}

func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	defer func() { _ = ln.Close() }()

	return ln.Addr().String()
}

func status(url string) int {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()

	return resp.StatusCode
}

func waitForStatus(t *testing.T, url string, want int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for status(url) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not answer %d within %s", url, want, timeout)
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// messages returns the msg field of every JSON log line. Call it only after
// the service has stopped, so nothing is writing to the buffer.
func messages(t *testing.T, logs *bytes.Buffer) []string {
	t.Helper()

	var msgs []string

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec struct {
			Msg string `json:"msg"`
		}

		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v: %q", err, line)
		}

		msgs = append(msgs, rec.Msg)
	}

	return msgs
}

// clientConnections counts the connections to the database other than the
// caller's own.
func clientConnections(t *testing.T, conn *pgx.Conn) int {
	t.Helper()

	var n int

	err := conn.QueryRow(t.Context(), `
		SELECT count(*) FROM pg_stat_activity
		WHERE datname = $1 AND backend_type = 'client backend' AND pid <> pg_backend_pid()`,
		database).Scan(&n)
	if err != nil {
		t.Fatalf("count connections: %v", err)
	}

	return n
}

func TestShutdownClosesTheDatabaseAfterTheServer(t *testing.T) {
	_, dsn := startPostgres(t)
	svc := startService(t, dsn)

	waitForStatus(t, "http://"+svc.addr+"/readyz", http.StatusOK, 15*time.Second)

	admin, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connect as observer: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	if n := clientConnections(t, admin); n == 0 {
		t.Fatal("the service holds no database connections while running")
	}

	if err = svc.stop(); err != nil {
		t.Fatalf("Run = %v, want nil after a requested shutdown", err)
	}

	msgs := messages(t, svc.logs)
	serverStopped := slices.Index(msgs, "http server stopped")
	databaseClosed := slices.Index(msgs, "database closed")

	if serverStopped < 0 || databaseClosed < 0 {
		t.Fatalf("log messages = %q, want both %q and %q", msgs, "http server stopped", "database closed")
	}

	if serverStopped > databaseClosed {
		t.Errorf("the database was closed before the server stopped: %q", msgs)
	}

	deadline := time.Now().Add(5 * time.Second)

	for clientConnections(t, admin) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the service still holds database connections after Run returned")
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func TestReadyzReportsUnavailableWhenTheDatabaseGoesDown(t *testing.T) {
	ctr, dsn := startPostgres(t)
	svc := startService(t, dsn)

	base := "http://" + svc.addr
	waitForStatus(t, base+"/readyz", http.StatusOK, 15*time.Second)

	if err := ctr.Stop(t.Context(), nil); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}

	waitForStatus(t, base+"/readyz", http.StatusServiceUnavailable, 15*time.Second)

	if got := status(base + "/healthz"); got != http.StatusOK {
		t.Errorf("/healthz = %d, want %d: liveness must not depend on the database", got, http.StatusOK)
	}

	if err := svc.stop(); err != nil {
		t.Fatalf("Run = %v, want nil: shutdown must work without a database", err)
	}

	if msgs := messages(t, svc.logs); !slices.Contains(msgs, "readiness check failed") {
		t.Errorf("log messages = %q, want the readiness failure to be logged", msgs)
	}
}

func TestDataSurvivesARestart(t *testing.T) {
	_, dsn := startPostgres(t)
	applyMigrations(t, dsn)

	first := startService(t, dsn)
	waitForStatus(t, "http://"+first.addr+"/readyz", http.StatusOK, 15*time.Second)
	created := createThreat(t, "http://"+first.addr, hashN(1), "Persisted")

	if err := first.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	second := startService(t, dsn)
	waitForStatus(t, "http://"+second.addr+"/readyz", http.StatusOK, 15*time.Second)

	code, got := call(t, http.MethodGet, "http://"+second.addr+"/info/"+hashN(1), "")
	if code != http.StatusOK || !reflect.DeepEqual(got, created) {
		t.Errorf("GET after a restart = %d %v, want %v", code, got, created)
	}
}
