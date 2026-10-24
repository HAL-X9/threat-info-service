package router

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

type okDB struct{}

func (okDB) Ping(context.Context) error { return nil }

func TestRoutes(t *testing.T) {
	handler := New(slog.New(slog.NewTextHandler(io.Discard, nil)), okDB{})

	tests := map[string]struct {
		method string
		path   string
		want   int
	}{
		"healthz":        {http.MethodGet, "/healthz", http.StatusOK},
		"healthz head":   {http.MethodHead, "/healthz", http.StatusOK},
		"healthz method": {http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		"readyz":         {http.MethodGet, "/readyz", http.StatusOK},
		"readyz method":  {http.MethodPost, "/readyz", http.StatusMethodNotAllowed},
		"unknown path":   {http.MethodGet, "/nope", http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}
