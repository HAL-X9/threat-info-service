package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func serveID(clientIDs ...string) (request, response string) {
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header[RequestIDHeader] = clientIDs

	rec := httptest.NewRecorder()
	RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		request = r.Header.Get(RequestIDHeader)
	})).ServeHTTP(rec, req)

	return request, rec.Header().Get(RequestIDHeader)
}

func TestRequestIDGeneratesOneWhenMissing(t *testing.T) {
	request, response := serveID()

	if !uuidV7.MatchString(request) || request != response {
		t.Errorf("request id = %q, response id = %q, want the same UUIDv7", request, response)
	}
}

func TestRequestIDKeepsAWellFormedClientID(t *testing.T) {
	for _, id := range []string{"abc-123", "trace/42:7", strings.Repeat("x", maxRequestIDLength)} {
		if request, response := serveID(id); request != id || response != id {
			t.Errorf("id %q became request %q, response %q", id, request, response)
		}
	}
}

func TestRequestIDReplacesAMalformedClientID(t *testing.T) {
	tests := map[string][]string{
		"empty":         {""},
		"space":         {"two words"},
		"newline":       {"line\nbreak"},
		"control":       {"a\x00b"},
		"non ascii":     {"идентификатор"},
		"too long":      {strings.Repeat("x", maxRequestIDLength+1)},
		"several lines": {"one", "two"},
	}

	for name, ids := range tests {
		t.Run(name, func(t *testing.T) {
			request, response := serveID(ids...)

			if !uuidV7.MatchString(request) || request != response {
				t.Errorf("request id = %q, response id = %q, want a generated UUIDv7", request, response)
			}
		})
	}
}
