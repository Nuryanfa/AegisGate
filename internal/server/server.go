package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Options contains explicit HTTP server settings.
type Options struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// Server owns the HTTP listener lifecycle.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

func New(options Options, handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:              options.Addr,
			Handler:           handler,
			ReadTimeout:       options.ReadTimeout,
			ReadHeaderTimeout: options.ReadTimeout,
			WriteTimeout:      options.WriteTimeout,
			IdleTimeout:       options.IdleTimeout,
		},
		logger: logger,
	}
}

// Run serves until startup fails or ctx is cancelled, then drains active
// requests within shutdownTimeout.
func (s *Server) Run(ctx context.Context, shutdownTimeout time.Duration) error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.httpServer.Addr, err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		s.logger.Info("HTTP server starting", "address", listener.Addr().String())
		serveErrors <- s.httpServer.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		s.logger.Info("HTTP server shutdown started", "timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		_ = s.httpServer.Close()
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	s.logger.Info("HTTP server shutdown completed")
	return nil
}

// ReadinessCheck can be extended with dependency checks in later milestones.
type ReadinessCheck func(context.Context) error

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeStatus(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	writeStatus(w, http.StatusOK, "ok")
}

func ReadinessHandler(checks ...ReadinessCheck) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeStatus(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		for _, check := range checks {
			if err := check(r.Context()); err != nil {
				writeStatus(w, http.StatusServiceUnavailable, "not_ready")
				return
			}
		}
		writeStatus(w, http.StatusOK, "ok")
	})
}

func writeStatus(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
	}{Status: value})
}
