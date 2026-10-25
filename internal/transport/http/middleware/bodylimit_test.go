package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxBodyPassesSmallBodiesThrough(t *testing.T) {
	tests := map[string]string{
		"below the limit": "12345",
		"at the limit":    "1234567890",
		"empty":           "",
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var got string

			handler := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("ReadAll: %v", err)
				}

				got = string(data)
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(body)))

			if rec.Code != http.StatusOK || got != body {
				t.Errorf("status = %d, body = %q, want 200 and %q", rec.Code, got, body)
			}
		})
	}
}

func TestMaxBodyRejectsADeclaredOversizedBody(t *testing.T) {
	called := false

	handler := MaxBody(10)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/info", strings.NewReader(strings.Repeat("x", 11))))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}

	if called {
		t.Error("the handler ran although the body was declared too large")
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestMaxBodyStopsAnOversizedBodyOfUnknownLength(t *testing.T) {
	var readErr error

	handler := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))

	req := httptest.NewRequest(http.MethodPost, "/info", io.NopCloser(strings.NewReader(strings.Repeat("x", 100))))
	req.ContentLength = -1

	handler.ServeHTTP(httptest.NewRecorder(), req)

	var tooLarge *http.MaxBytesError
	if !errors.As(readErr, &tooLarge) || tooLarge.Limit != 10 {
		t.Errorf("read error = %v, want *http.MaxBytesError with limit 10", readErr)
	}
}
