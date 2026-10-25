package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}

				if v == http.ErrAbortHandler {
					panic(v)
				}

				log.ErrorContext(r.Context(), "panic recovered",
					"request_id", r.Header.Get(RequestIDHeader), "method", r.Method, "path", r.URL.Path,
					"panic", v, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "Internal server error")
			}()

			next.ServeHTTP(w, r)
		})
	}
}
