package httpserver

import (
	"context"
	"crypto/tls"
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
	tls bool
	log *slog.Logger
}

// New configures a server for handler and, when the configuration enables TLS,
// loads the certificate, so that an unusable one fails at startup. It does not
// open the listener.
func New(cfg config.HTTPServer, handler http.Handler, log *slog.Logger) (*Server, error) {
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadTimeout:       cfg.Timeouts.ReadTimeout,
		ReadHeaderTimeout: cfg.Timeouts.ReadHeaderTimeout,
		WriteTimeout:      cfg.Timeouts.WriteTimeout,
		IdleTimeout:       cfg.Timeouts.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	if cfg.TLS.Enabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load the TLS certificate: %w", err)
		}

		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}

	return &Server{srv: srv, tls: cfg.TLS.Enabled(), log: log}, nil
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
	go func() { served <- s.serve(ln) }()

	s.log.Info("http server ready", "addr", ln.Addr().String(), "tls", s.tls)

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

func (s *Server) serve(ln net.Listener) error {
	if s.tls {
		return s.srv.ServeTLS(ln, "", "")
	}

	return s.srv.Serve(ln)
}
