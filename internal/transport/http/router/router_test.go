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

func newRouter(logs *bytes.Buffer, limits Limits) http.Handler {
	return New(slog.New(slog.NewJSONHandler(logs, nil)), okDB{}, emptyService{}, limits)
}

var roomy = Limits{RequestsPerSecond: 1000, Burst: 1000, MaxBodyBytes: 1 << 16}

func TestRoutes(t *testing.T) {
	handler := newRouter(new(bytes.Buffer), roomy)

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

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}

func TestOnlyAPIRequestsAreLogged(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(&logs, roomy)

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

func serve(handler http.Handler, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1000"

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func TestAPIRequestsPassThroughTheChain(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(&logs, Limits{RequestsPerSecond: 1000, Burst: 1000, MaxBodyBytes: 10})

	tests := map[string]struct {
		method      string
		contentType string
		body        string
		want        int
	}{
		"valid json within the limit": {http.MethodPost, "application/json", "{}", http.StatusBadRequest},
		"wrong content type":          {http.MethodPost, "text/plain", "{}", http.StatusUnsupportedMediaType},
		"body over the limit":         {http.MethodPost, "application/json", strings.Repeat("x", 11), http.StatusRequestEntityTooLarge},
		"get needs no content type":   {http.MethodGet, "", "", http.StatusBadRequest},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := "/info"
			if tc.method == http.MethodGet {
				path = "/info/abc"
			}

			rec := serve(handler, tc.method, path, tc.contentType, tc.body)

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}

			if rec.Header().Get(middleware.RequestIDHeader) == "" {
				t.Error("the response has no request id, even for a rejected request")
			}
		})
	}

	if got := strings.Count(logs.String(), `"request_id":""`); got != 0 {
		t.Errorf("%d log lines have an empty request_id: %s", got, logs.String())
	}
}

func TestAPIRequestIDFromTheClientIsEchoedAndLogged(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(&logs, roomy)

	req := httptest.NewRequest(http.MethodGet, "/info/abc", nil)
	req.Header.Set(middleware.RequestIDHeader, "client-42")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(middleware.RequestIDHeader); got != "client-42" {
		t.Errorf("response request id = %q, want client-42", got)
	}

	if !strings.Contains(logs.String(), `"request_id":"client-42"`) {
		t.Errorf("the log lacks the request id: %s", logs.String())
	}
}

func TestRateLimitAppliesToTheAPIOnly(t *testing.T) {
	handler := newRouter(new(bytes.Buffer), Limits{RequestsPerSecond: 1, Burst: 1, MaxBodyBytes: 1 << 16})

	if got := serve(handler, http.MethodGet, "/info/abc", "", "").Code; got != http.StatusBadRequest {
		t.Fatalf("first API request = %d, want %d", got, http.StatusBadRequest)
	}

	rejected := serve(handler, http.MethodGet, "/info/abc", "", "")
	if rejected.Code != http.StatusTooManyRequests || rejected.Header().Get(middleware.RequestIDHeader) == "" {
		t.Errorf("second API request = %d, want %d with a request id", rejected.Code, http.StatusTooManyRequests)
	}

	for range 5 {
		probe := serve(handler, http.MethodGet, "/healthz", "", "")
		if probe.Code != http.StatusOK || probe.Header().Get(middleware.RequestIDHeader) != "" {
			t.Fatalf("/healthz = %d with request id %q, want an unlimited probe outside the chain", probe.Code, probe.Header().Get(middleware.RequestIDHeader))
		}
	}
}
