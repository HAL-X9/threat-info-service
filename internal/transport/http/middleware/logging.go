package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Logging logs one line per handled request: method, path, status, response
// size, duration and client address. The query string and the headers are
// never logged, since they may carry secrets.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusWriter{ResponseWriter: w}

			next.ServeHTTP(rw, r)

			status := rw.status()
			log.LogAttrs(r.Context(), level(status), "http request",
				slog.String("request_id", r.Header.Get(RequestIDHeader)),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Int64("bytes", rw.bytes),
				slog.Float64("duration_ms", float64(time.Since(start))/float64(time.Millisecond)),
				slog.String("remote_addr", remoteIP(r)),
			)
		})
	}
}

// level maps a status to a log level: server errors are errors, client errors
// are warnings.
func level(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// statusWriter records the status and the size of a response.
type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}

	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)

	return n, err
}

// status is 200 when the handler wrote nothing, as net/http does.
func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}

	return w.code
}

// Unwrap lets http.ResponseController reach Flush and the other optional
// interfaces of the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
