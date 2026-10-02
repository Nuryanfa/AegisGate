package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/observability"
)

type Telemetry struct {
	server   *http.Server
	listener net.Listener
	errors   chan error
	done     chan struct{}
}

func StartTelemetry(options observability.MetricsOptions, handler http.Handler, logger *slog.Logger) (*Telemetry, error) {
	listener, err := net.Listen("tcp", options.Address)
	if err != nil {
		return nil, fmt.Errorf("bind telemetry listener: %w", err)
	}
	t := &Telemetry{listener: listener, errors: make(chan error, 1), done: make(chan struct{}), server: &http.Server{
		Handler: handler, ReadTimeout: options.ReadTimeout, ReadHeaderTimeout: options.ReadTimeout,
		WriteTimeout: options.WriteTimeout, IdleTimeout: options.ReadTimeout,
	}}
	go func() {
		defer close(t.done)
		logger.Info("telemetry server starting", "address", listener.Addr().String())
		if err := t.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.errors <- fmt.Errorf("telemetry server stopped unexpectedly: %w", err)
		}
	}()
	return t, nil
}

func (t *Telemetry) Errors() <-chan error { return t.errors }
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}
	err := t.server.Shutdown(ctx)
	if err != nil {
		_ = t.server.Close()
	}
	select {
	case <-t.done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

// RunWithTelemetry watches both listeners and drains HTTP before telemetry.
func RunWithTelemetry(ctx context.Context, gateway *Server, telemetry *Telemetry, gatewayTimeout, telemetryTimeout time.Duration) error {
	if telemetry == nil {
		return gateway.Run(ctx, gatewayTimeout)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(runCtx, gatewayTimeout) }()
	var gatewayErr, telemetryErr error
	select {
	case gatewayErr = <-gatewayDone:
	case telemetryErr = <-telemetry.Errors():
		cancel()
		gatewayErr = <-gatewayDone
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), telemetryTimeout)
	defer stop()
	shutdownErr := telemetry.Shutdown(shutdownCtx)
	select {
	case err := <-telemetry.Errors():
		telemetryErr = errors.Join(telemetryErr, err)
	default:
	}
	return errors.Join(gatewayErr, telemetryErr, shutdownErr)
}
