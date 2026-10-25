package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
	"github.com/HAL-X9/threat-info-service/internal/httpserver"
	"github.com/HAL-X9/threat-info-service/internal/postgres"
	"github.com/HAL-X9/threat-info-service/internal/repository"
	"github.com/HAL-X9/threat-info-service/internal/service"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/middleware"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/router"
)

type App struct {
	cfg *config.Config
	log *slog.Logger
}

// New loads and validates the configuration and builds the logger, which
// writes to stderr. It does no network I/O: nothing is opened until Run.
func New(args []string, getenv func(string) string, stderr io.Writer) (*App, error) {
	configPath, err := parseFlags(args)
	if err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	path := config.ResolvePath(configPath, getenv)

	cfg, err := config.Load(path, getenv)
	if err != nil {
		return nil, fmt.Errorf("load config (%s): %w", path, err)
	}

	log := newLogger(stderr, cfg.Log.Level)
	log.Info("configuration loaded", "path", path, "log_level", cfg.Log.Level.String())

	return &App{cfg: cfg, log: log}, nil
}

// Run builds the dependencies and serves until ctx is canceled or the server
// fails. It returns nil on a requested shutdown.
func (a *App) Run(ctx context.Context) error {
	pool, err := postgres.NewPool(ctx, a.cfg.Database)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.log.Info("database connected",
		"min_conns", a.cfg.Database.Pool.MinConns,
		"max_conns", a.cfg.Database.Pool.MaxConns,
	)
	// Closed only after the server has stopped.
	defer func() {
		pool.Close()
		a.log.Info("database closed")
	}()

	threats := service.New(repository.NewThreats(pool, a.cfg.Database.Timeouts.Query), time.Now)

	rateLimit := a.cfg.HTTPServer.RateLimit
	handler := router.New(a.log, pool, threats, middleware.RateLimit(rateLimit.RequestsPerSecond, rateLimit.Burst))

	server := httpserver.New(a.cfg.HTTPServer, handler, a.log)

	return server.Run(ctx)
}

// parseFlags uses a private FlagSet, so New can be called more than once.
func parseFlags(args []string) (configPath string, err error) {
	fs := flag.NewFlagSet("threat-info-service", flag.ContinueOnError)
	fs.StringVar(&configPath, "config", "", "path to the YAML config (overrides "+config.EnvConfigPath+")")

	if err = fs.Parse(args); err != nil {
		return "", err
	}

	return configPath, nil
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}
