package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

const shutdownTimeout = 15 * time.Second

// Server is an HTTP server with graceful shutdown.
type Server struct {
	srv *http.Server
	log *slog.Logger
}

// New configures a server for handler. It does not open the listener.
func New(cfg config.HTTPServer, handler http.Handler, log *slog.Logger) *Server {
	return &Server{
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			ReadTimeout:       cfg.Timeouts.ReadTimeout,
			ReadHeaderTimeout: cfg.Timeouts.ReadHeaderTimeout,
			WriteTimeout:      cfg.Timeouts.WriteTimeout,
			IdleTimeout:       cfg.Timeouts.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
		},
		log: log,
	}
}

// Run serves until ctx is canceled or the server fails. On cancellation it
// gives in-flight requests shutdownTimeout to finish and returns nil.
func (s *Server) Run(ctx context.Context) error {
	// Bind first, so a taken port fails fast.
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	served := make(chan error, 1)
	go func() { served <- s.srv.Serve(ln) }()

	s.log.Info("http server ready", "addr", ln.Addr().String())

	select {
	case err = <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	s.log.Info("http server shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if err = s.srv.Shutdown(shutdownCtx); err != nil {
		return errors.Join(fmt.Errorf("shutdown: %w", err), s.srv.Close())
	}

	// Serve returns http.ErrServerClosed once Shutdown has been called.
	<-served

	s.log.Info("http server stopped")

	return nil
}
