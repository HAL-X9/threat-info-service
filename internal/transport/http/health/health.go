package health

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

const readinessTimeout = 2 * time.Second

// Pinger checks that a dependency is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Liveness reports that the process is alive.
func Liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Readiness answers 200 when db responds within readinessTimeout and 503
// otherwise. The failure reason is logged, never returned to the client.
func Readiness(log *slog.Logger, db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			log.WarnContext(r.Context(), "readiness check failed", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
