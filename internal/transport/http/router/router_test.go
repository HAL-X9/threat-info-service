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

const (
	hash       = "d41d8cd98f00b204e9800998ecf8427e"
	token      = "local-test-token-12345"
	validBody  = `{"md5":"` + hash + `","name":"x","severity":"low","category":"worm"}`
	authHeader = "Bearer " + token
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

var roomy = Options{RequestsPerSecond: 1000, Burst: 1000, MaxBodyBytes: 1 << 16, APIToken: token}

func newRouter(t *testing.T, logs *bytes.Buffer, opts Options) http.Handler {
	t.Helper()

	handler, err := New(slog.New(slog.NewJSONHandler(logs, nil)), okDB{}, emptyService{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return handler
}

func serve(handler http.Handler, method, path, contentType, authorization, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1000"

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func TestRoutes(t *testing.T) {
	handler := newRouter(t, new(bytes.Buffer), roomy)

	tests := map[string]struct {
		method string
		path   string
		body   string
		want   int
	}{
		"healthz":            {http.MethodGet, "/healthz", "", http.StatusOK},
		"healthz head":       {http.MethodHead, "/healthz", "", http.StatusOK},
		"healthz method":     {http.MethodPost, "/healthz", "", http.StatusMethodNotAllowed},
		"readyz":             {http.MethodGet, "/readyz", "", http.StatusOK},
		"readyz method":      {http.MethodPost, "/readyz", "", http.StatusMethodNotAllowed},
		"get unknown":        {http.MethodGet, "/info/" + hash, "", http.StatusNotFound},
		"get invalid hash":   {http.MethodGet, "/info/abc", "", http.StatusBadRequest},
		"create":             {http.MethodPost, "/info", validBody, http.StatusNotFound},
		"create invalid":     {http.MethodPost, "/info", "{}", http.StatusBadRequest},
		"unsupported method": {http.MethodDelete, "/info/" + hash, "", http.StatusMethodNotAllowed},
		"unknown path":       {http.MethodGet, "/nope", "", http.StatusNotFound},
		"unknown api path":   {http.MethodGet, "/info/" + hash + "/extra", "", http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := serve(handler, tc.method, tc.path, "application/json", authHeader, tc.body)

			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}

func TestWritesRequireAToken(t *testing.T) {
	handler := newRouter(t, new(bytes.Buffer), roomy)

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		path := "/info"
		if method == http.MethodPut {
			path = "/info/" + hash
		}

		body := validBody
		if method == http.MethodPut {
			body = `{"name":"x","severity":"low","category":"worm"}`
		}

		rec := serve(handler, method, path, "application/json", "", body)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s without a token = %d, want 401 with WWW-Authenticate", method, rec.Code)
		}

		if rec = serve(handler, method, path, "application/json", authHeader, body); rec.Code != http.StatusNotFound {
			t.Errorf("%s with a token = %d, want %d: the request must reach the handler", method, rec.Code, http.StatusNotFound)
		}
	}

	if rec := serve(handler, http.MethodGet, "/info/"+hash, "", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET without a token = %d, want %d: reads are open", rec.Code, http.StatusNotFound)
	}
}

func TestOnlyAPIRequestsAreLogged(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(t, &logs, roomy)

	for _, path := range []string{"/healthz", "/readyz"} {
		serve(handler, http.MethodGet, path, "", "", "")
	}

	if logs.Len() != 0 {
		t.Fatalf("probes were logged: %s", logs.String())
	}

	serve(handler, http.MethodGet, "/info/abc", "", "", "")

	if !strings.Contains(logs.String(), `"path":"/info/abc"`) {
		t.Errorf("the API request was not logged: %q", logs.String())
	}
}

func TestAPIRequestsPassThroughTheChain(t *testing.T) {
	var logs bytes.Buffer

	opts := roomy
	opts.MaxBodyBytes = 10
	handler := newRouter(t, &logs, opts)

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

			rec := serve(handler, tc.method, path, tc.contentType, authHeader, tc.body)

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}

			if rec.Header().Get(middleware.RequestIDHeader) == "" {
				t.Error("the response has no request id, even for a rejected request")
			}
		})
	}

	if strings.Contains(logs.String(), `"request_id":""`) {
		t.Errorf("a log line has an empty request_id: %s", logs.String())
	}
}

func TestAPIRequestIDFromTheClientIsEchoedAndLogged(t *testing.T) {
	var logs bytes.Buffer

	handler := newRouter(t, &logs, roomy)

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
	opts := roomy
	opts.RequestsPerSecond, opts.Burst = 1, 1
	handler := newRouter(t, new(bytes.Buffer), opts)

	if got := serve(handler, http.MethodGet, "/info/abc", "", "", "").Code; got != http.StatusBadRequest {
		t.Fatalf("first API request = %d, want %d", got, http.StatusBadRequest)
	}

	rejected := serve(handler, http.MethodGet, "/info/abc", "", "", "")
	if rejected.Code != http.StatusTooManyRequests || rejected.Header().Get(middleware.RequestIDHeader) == "" {
		t.Errorf("second API request = %d, want %d with a request id", rejected.Code, http.StatusTooManyRequests)
	}

	for range 5 {
		probe := serve(handler, http.MethodGet, "/healthz", "", "", "")
		if probe.Code != http.StatusOK || probe.Header().Get(middleware.RequestIDHeader) != "" {
			t.Fatalf("/healthz = %d with request id %q, want an unlimited probe outside the chain", probe.Code, probe.Header().Get(middleware.RequestIDHeader))
		}
	}
}
