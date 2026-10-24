package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type pingFunc func(ctx context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readyz(db Pinger) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Readiness(discardLogger(), db).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	return rec
}

func TestLiveness(t *testing.T) {
	rec := httptest.NewRecorder()

	Liveness(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadiness(t *testing.T) {
	tests := map[string]struct {
		err  error
		want int
	}{
		"database responds": {nil, http.StatusOK},
		"database is down":  {errors.New("connection refused"), http.StatusServiceUnavailable},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := readyz(pingFunc(func(context.Context) error { return tc.err }))

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestReadinessBoundsThePing(t *testing.T) {
	rec := readyz(pingFunc(func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("ping context has no deadline")
		}

		return nil
	}))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: the ping must run under a deadline", rec.Code, http.StatusOK)
	}
}

func TestReadinessDoesNotExposeTheFailureReason(t *testing.T) {
	rec := readyz(pingFunc(func(context.Context) error {
		return errors.New("password authentication failed")
	}))

	if body := rec.Body.String(); strings.Contains(body, "password") {
		t.Errorf("body leaks the failure reason: %q", body)
	}
}
