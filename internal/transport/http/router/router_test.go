package router

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HAL-X9/threat-info-service/internal/domain"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/middleware"
)

type okDB struct{}

func (okDB) Ping(context.Context) error { return nil }

type emptyService struct{}

func (emptyService) Create(context.Context, domain.MD5, domain.Details) (domain.Threat, error) {
	return domain.Threat{}, domain.ErrNotFound
}

func (emptyService) Get(context.Context, domain.MD5) (domain.Threat, error) {
	return domain.Threat{}, domain.ErrNotFound
}

func (emptyService) Update(context.Context, domain.MD5, domain.Details) (domain.Threat, error) {
	return domain.Threat{}, domain.ErrNotFound
}

func newRouter(logs *bytes.Buffer, middlewares ...func(http.Handler) http.Handler) http.Handler {
	return New(slog.New(slog.NewJSONHandler(logs, nil)), okDB{}, emptyService{}, middlewares...)
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

func TestMiddlewaresWrapOnlyTheAPI(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(&logs, middleware.RateLimit(1, 1))

	status := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.0.2.1:1000"

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec.Code
	}

	if got := status("/info/abc"); got != http.StatusBadRequest {
		t.Fatalf("first API request = %d, want %d", got, http.StatusBadRequest)
	}

	if got := status("/info/abc"); got != http.StatusTooManyRequests {
		t.Errorf("second API request = %d, want %d", got, http.StatusTooManyRequests)
	}

	for range 5 {
		if got := status("/healthz"); got != http.StatusOK {
			t.Fatalf("/healthz = %d, want %d: probes must not be rate limited", got, http.StatusOK)
		}
	}

	if !strings.Contains(logs.String(), `"status":429`) {
		t.Errorf("the rejected request was not logged: %q", logs.String())
	}
}
