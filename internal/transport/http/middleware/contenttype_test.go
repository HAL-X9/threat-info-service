package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireJSON(t *testing.T) {
	tests := map[string]struct {
		method      string
		contentType string
		want        int
	}{
		"post json":              {http.MethodPost, "application/json", http.StatusOK},
		"post json with charset": {http.MethodPost, "application/json; charset=utf-8", http.StatusOK},
		"put json":               {http.MethodPut, "application/json", http.StatusOK},
		"post form":              {http.MethodPost, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		"post text":              {http.MethodPost, "text/plain", http.StatusUnsupportedMediaType},
		"post without type":      {http.MethodPost, "", http.StatusUnsupportedMediaType},
		"post malformed type":    {http.MethodPost, "application/json;;;=", http.StatusUnsupportedMediaType},
		"put text":               {http.MethodPut, "text/plain", http.StatusUnsupportedMediaType},
		"get without type":       {http.MethodGet, "", http.StatusOK},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/info", nil)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			rec := httptest.NewRecorder()
			RequireJSON(ok).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}

			if tc.want != http.StatusOK && rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q, want an ErrorResponse in JSON", rec.Header().Get("Content-Type"))
			}
		})
	}
}
