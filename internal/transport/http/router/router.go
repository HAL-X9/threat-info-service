package router

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/transport/http/gen"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/health"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/middleware"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/threat"
)

type Options struct {
	RequestsPerSecond float64
	Burst             int
	MaxBodyBytes      int64
	APIToken          string
}

func New(log *slog.Logger, db health.Pinger, threats threat.Service, opts Options) (http.Handler, error) {
	spec, err := gen.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("load the OpenAPI spec: %w", err)
	}

	api := http.NewServeMux()
	threat.NewHandler(threats, log).Register(api)

	handler := middleware.Chain(
		middleware.RequestID,
		middleware.Logging(log),
		middleware.RateLimit(opts.RequestsPerSecond, opts.Burst),
		middleware.MaxBody(opts.MaxBodyBytes),
		middleware.RequireJSON,
		middleware.OpenAPI(spec, opts.APIToken),
	)(api)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)
	mux.Handle("GET /readyz", health.Readiness(log, db))
	mux.Handle("/info", handler)
	mux.Handle("/info/", handler)

	return mux, nil
}
