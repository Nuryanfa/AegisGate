package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/observability"
)

func telemetryOptions(address string) observability.MetricsOptions {
	return observability.MetricsOptions{Enabled: true, Address: address, Path: "/metrics", ReadTimeout: time.Second, WriteTimeout: time.Second, ShutdownTimeout: time.Second}
}

func TestTelemetryListenerLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := observability.NewMetrics("dev", "unknown", "unknown", nil)
	telemetry, err := StartTelemetry(telemetryOptions("127.0.0.1:0"), metrics.Handler("/metrics"), logger)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + telemetry.listener.Addr().String() + "/metrics"
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	if err := telemetry.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-telemetry.done:
	default:
		t.Fatal("serve goroutine still active")
	}
}

func TestTelemetryBindFailureAndUnexpectedStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := StartTelemetry(telemetryOptions(listener.Addr().String()), http.NotFoundHandler(), logger); err == nil {
		t.Fatal("expected bind error")
	}

	telemetry, err := StartTelemetry(telemetryOptions("127.0.0.1:0"), http.NotFoundHandler(), logger)
	if err != nil {
		t.Fatal(err)
	}
	gateway := New(Options{Addr: "127.0.0.1:0", ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second}, http.NotFoundHandler(), logger)
	closed := make(chan struct{})
	go func() { time.Sleep(20 * time.Millisecond); _ = telemetry.listener.Close(); close(closed) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = RunWithTelemetry(ctx, gateway, telemetry, time.Second, time.Second)
	<-closed
	if err == nil || !strings.Contains(err.Error(), "telemetry server stopped unexpectedly") {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestRunWithTelemetryDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gateway := New(Options{Addr: "127.0.0.1:0", ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second}, http.NotFoundHandler(), logger)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := RunWithTelemetry(ctx, gateway, nil, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
}
