package router

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/memory"
	"github.com/HAL-X9/threat-info-service/internal/service"
)

type okDB struct{}

func (okDB) Ping(context.Context) error { return nil }

func newRouter(logs *bytes.Buffer) http.Handler {
	svc := service.New(memory.New(), time.Now)

	return New(slog.New(slog.NewJSONHandler(logs, nil)), okDB{}, svc)
}

func TestRoutes(t *testing.T) {
	handler := newRouter(new(bytes.Buffer))

	tests := map[string]struct {
		method string
		path   string
		body   string
		want   int
	}{
		"healthz":             {http.MethodGet, "/healthz", "", http.StatusOK},
		"healthz head":        {http.MethodHead, "/healthz", "", http.StatusOK},
		"healthz method":      {http.MethodPost, "/healthz", "", http.StatusMethodNotAllowed},
		"readyz":              {http.MethodGet, "/readyz", "", http.StatusOK},
		"readyz method":       {http.MethodPost, "/readyz", "", http.StatusMethodNotAllowed},
		"get unknown threat":  {http.MethodGet, "/info/d41d8cd98f00b204e9800998ecf8427e", "", http.StatusNotFound},
		"get invalid md5":     {http.MethodGet, "/info/abc", "", http.StatusBadRequest},
		"create invalid body": {http.MethodPost, "/info", "{}", http.StatusBadRequest},
		"unsupported method":  {http.MethodDelete, "/info/d41d8cd98f00b204e9800998ecf8427e", "", http.StatusMethodNotAllowed},
		"unknown path":        {http.MethodGet, "/nope", "", http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))

			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}

func TestOnlyAPIRequestsAreLogged(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(&logs)

	for _, path := range []string{"/healthz", "/readyz"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	if logs.Len() != 0 {
		t.Fatalf("probes were logged: %s", logs.String())
	}

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/info/abc", nil))

	if !strings.Contains(logs.String(), `"path":"/info/abc"`) {
		t.Errorf("the API request was not logged: %q", logs.String())
	}
}
