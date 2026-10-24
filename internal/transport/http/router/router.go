package router

import (
	"log/slog"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/transport/http/health"
)

// New returns the handler serving every route of the service.
func New(log *slog.Logger, db health.Pinger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.Handle("GET /readyz", health.Readiness(log, db))

	return mux
}
