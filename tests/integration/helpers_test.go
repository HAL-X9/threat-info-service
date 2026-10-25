//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func applyMigrations(t *testing.T, dsn string) {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("find migrations: %v (%d files)", err, len(files))
	}

	slices.Sort(files)

	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}

		up, _, _ := strings.Cut(string(data), "-- +goose Down")
		up = strings.Replace(up, "-- +goose Up", "", 1)

		if _, err = conn.Exec(t.Context(), up); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}
}

func newAPI(t *testing.T) string {
	t.Helper()

	_, dsn := startPostgres(t)
	applyMigrations(t, dsn)

	svc := startService(t, dsn)
	base := "http://" + svc.addr
	waitForStatus(t, base+"/readyz", http.StatusOK, 15*time.Second)

	return base
}

const apiToken = "local-test-token-12345"

func call(t *testing.T, method, url, body string) (int, map[string]any) {
	t.Helper()

	return callAs(t, "Bearer "+apiToken, method, url, body)
}

func callAs(t *testing.T, authorization, method, url, body string) (int, map[string]any) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("%s %s: the body is not JSON: %v", method, url, err)
	}

	return resp.StatusCode, out
}

func wantStatus(t *testing.T, got, want int, body map[string]any) {
	t.Helper()

	if got != want {
		t.Fatalf("status = %d, want %d: %v", got, want, body)
	}
}

func wantMessage(t *testing.T, body map[string]any) {
	t.Helper()

	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("body = %v, want an ErrorResponse with a message", body)
	}
}

func hashN(n int) string {
	return fmt.Sprintf("%032x", n)
}

func threatJSON(md5, name string) string {
	return fmt.Sprintf(`{"md5":%q,"name":%q,"severity":"high","category":"trojan"}`, md5, name)
}

func putJSON(name string) string {
	return fmt.Sprintf(`{"name":%q,"severity":"low","category":"worm"}`, name)
}

func createThreat(t *testing.T, base, md5, name string) map[string]any {
	t.Helper()

	code, body := call(t, http.MethodPost, base+"/info", threatJSON(md5, name))
	wantStatus(t, code, http.StatusCreated, body)

	return body
}
