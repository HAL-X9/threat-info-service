package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

// App is the process composition root. Construct it once with New and run it
// once with Run.
type App struct {
	cfg *config.Config
	log *slog.Logger
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

	return &App{cfg: cfg, log: log}, nil
}

// Run blocks until ctx is canceled or a component fails, and returns only
// after everything it started has stopped. It returns nil on a requested
// shutdown.
func (a *App) Run(ctx context.Context) error {
	a.log.Info("service started")

	<-ctx.Done()

	a.log.Info("service stopped")

	return nil
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
