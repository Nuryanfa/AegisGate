package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	serviceName := environment("EXAMPLE_SERVICE_NAME", "example-upstream")
	httpAddr := environment("EXAMPLE_HTTP_ADDR", ":8081")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Service string `json:"service"`
			Status  string `json:"status"`
			Path    string `json:"path"`
		}{
			Service: serviceName,
			Status:  "ok",
			Path:    r.URL.Path,
		})
	})

	httpServer := server.New(server.Options{
		Addr:         httpAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}, handler, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := httpServer.Run(ctx, 10*time.Second); err != nil {
		logger.Error("example upstream stopped with an error", "error", err)
		os.Exit(1)
	}
}

func environment(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
