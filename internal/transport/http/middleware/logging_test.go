package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serve runs one request through Logging and returns the single log record.
func serve(t *testing.T, handler http.HandlerFunc, req *http.Request) (rec map[string]any, raw string) {
	t.Helper()

	var out bytes.Buffer

	log := slog.New(slog.NewJSONHandler(&out, nil))
	Logging(log)(handler).ServeHTTP(httptest.NewRecorder(), req)

	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("log output is not a single JSON record: %v: %q", err, out.String())
	}

	return rec, out.String()
}

func TestLoggingRecordsTheRequest(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
		status  float64
		level   string
		bytes   float64
	}{
		"ok": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("created"))
			},
			status: http.StatusCreated, level: "INFO", bytes: 7,
		},
		"implicit 200": {
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) },
			status:  http.StatusOK, level: "INFO", bytes: 2,
		},
		"nothing written": {
			handler: func(http.ResponseWriter, *http.Request) {},
			status:  http.StatusOK, level: "INFO",
		},
		"client error": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
			status:  http.StatusNotFound, level: "WARN",
		},
		"server error": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			status:  http.StatusInternalServerError, level: "ERROR",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec, _ := serve(t, tc.handler, httptest.NewRequest(http.MethodPut, "/info/abc", nil))

			want := map[string]any{
				"msg":         "http request",
				"level":       tc.level,
				"method":      http.MethodPut,
				"path":        "/info/abc",
				"status":      tc.status,
				"bytes":       tc.bytes,
				"remote_addr": "192.0.2.1",
			}
			for key, v := range want {
				if rec[key] != v {
					t.Errorf("%s = %v, want %v", key, rec[key], v)
				}
			}

			if _, ok := rec["duration_ms"].(float64); !ok {
				t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
			}
		})
	}
}

func TestLoggingRecordsTheRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.Header.Set(RequestIDHeader, "abc-123")

	rec, _ := serve(t, func(http.ResponseWriter, *http.Request) {}, req)

	if rec["request_id"] != "abc-123" {
		t.Errorf("request_id = %v, want abc-123", rec["request_id"])
	}
}

func TestLoggingDoesNotRecordSecrets(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/info?token=query-secret", nil)
	req.Header.Set("Authorization", "Bearer header-secret")

	_, raw := serve(t, func(http.ResponseWriter, *http.Request) {}, req)

	for _, secret := range []string{"query-secret", "header-secret"} {
		if bytes.Contains([]byte(raw), []byte(secret)) {
			t.Errorf("log leaks %q: %s", secret, raw)
		}
	}
}

func TestLoggingKeepsOptionalWriterInterfaces(t *testing.T) {
	var flushErr error

	handler := func(w http.ResponseWriter, _ *http.Request) {
		flushErr = http.NewResponseController(w).Flush()
	}

	serve(t, handler, httptest.NewRequest(http.MethodGet, "/", nil))

	if flushErr != nil {
		t.Errorf("Flush through the wrapper: %v", flushErr)
	}
}
