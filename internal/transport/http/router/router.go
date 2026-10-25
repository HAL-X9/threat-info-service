package router

import (
	"log/slog"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/transport/http/health"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/middleware"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/threat"
)

type Limits struct {
	RequestsPerSecond float64
	Burst             int
	MaxBodyBytes      int64
}

func New(log *slog.Logger, db health.Pinger, threats threat.Service, limits Limits) http.Handler {
	api := http.NewServeMux()
	threat.NewHandler(threats, log).Register(api)

	handler := middleware.Chain(
		middleware.RequestID,
		middleware.Logging(log),
		middleware.RateLimit(limits.RequestsPerSecond, limits.Burst),
		middleware.MaxBody(limits.MaxBodyBytes),
		middleware.RequireJSON,
	)(api)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.Handle("GET /readyz", health.Readiness(log, db))
	mux.Handle("/info", handler)
	mux.Handle("/info/", handler)

	return mux
}
