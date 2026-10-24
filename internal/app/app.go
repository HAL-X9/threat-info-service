package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/health"
)

// shutdownTimeout bounds how long in-flight requests may drain on shutdown.
const shutdownTimeout = 15 * time.Second

type App struct {
	server *http.Server
	log    *slog.Logger
}

// New parses the flags, loads and validates the configuration and builds the
// dependencies. It performs no network I/O: nothing is opened until Run.
//
// args are the command-line arguments without the program name and getenv
// resolves environment variables; both are supplied by the caller.
func New(args []string, getenv func(string) string) (*App, error) {
	configPath, err := parseFlags(args)
	if err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	path := config.ResolvePath(configPath, getenv)

	cfg, err := config.Load(path, getenv)
	if err != nil {
		return nil, fmt.Errorf("load config (%s): %w", path, err)
	}

	log := newLogger(os.Stderr, cfg.Log.Level)

	server := &http.Server{
		Addr:              cfg.HTTPServer.Addr,
		Handler:           newHandler(),
		ReadTimeout:       cfg.HTTPServer.Timeouts.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTPServer.Timeouts.ReadHeaderTimeout,
		WriteTimeout:      cfg.HTTPServer.Timeouts.WriteTimeout,
		IdleTimeout:       cfg.HTTPServer.Timeouts.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTPServer.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	return &App{server: server, log: log}, nil
}

// Run serves HTTP until ctx is canceled or the server fails, and returns only
// after the server has stopped. In-flight requests get shutdownTimeout to
// finish. It returns nil on a requested shutdown.
func (a *App) Run(ctx context.Context) error {
	// Bind before serving, so a taken port fails Run immediately.
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", a.server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	served := make(chan error, 1)
	go func() { served <- a.server.Serve(ln) }()

	a.log.Info("service started", "addr", ln.Addr().String())

	select {
	case err = <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	a.log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if err = a.server.Shutdown(shutdownCtx); err != nil {
		return errors.Join(fmt.Errorf("shutdown: %w", err), a.server.Close())
	}

	// Shutdown makes Serve return http.ErrServerClosed at once.
	<-served

	a.log.Info("service stopped")

	return nil
}

// newHandler registers the routes of the HTTP API.
func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Liveness)

	return mux
}

// parseFlags parses args into a private FlagSet instead of the global
// flag.CommandLine, so New can be called more than once in a process.
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
