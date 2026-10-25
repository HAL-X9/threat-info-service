package router

import (
	"log/slog"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/transport/http/health"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/middleware"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/threat"
)

func New(log *slog.Logger, db health.Pinger, threats threat.Service, middlewares ...func(http.Handler) http.Handler) http.Handler {
	api := http.NewServeMux()
	threat.NewHandler(threats, log).Register(api)

	var handler http.Handler = api
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	handler = middleware.Logging(log)(handler)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.Handle("GET /readyz", health.Readiness(log, db))
	mux.Handle("/info", handler)
	mux.Handle("/info/", handler)

	return mux
}
