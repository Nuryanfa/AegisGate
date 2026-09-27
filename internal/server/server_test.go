package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandler(t *testing.T) {
	response := httptest.NewRecorder()
	HealthHandler(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
}

func TestReadinessHandlerReportsFailedCheck(t *testing.T) {
	handler := ReadinessHandler(func(_ context.Context) error {
		return errors.New("dependency unavailable")
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestServerRunShutsDownAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	time.AfterFunc(20*time.Millisecond, cancel)

	httpServer := New(Options{
		Addr:         "127.0.0.1:0",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		IdleTimeout:  time.Second,
	}, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := httpServer.Run(ctx, time.Second); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
