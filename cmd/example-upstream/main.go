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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Service string `json:"service"`
			Status  string `json:"status"`
			Path    string `json:"path"`
		}{
			Service: "example-upstream",
			Status:  "ok",
			Path:    r.URL.Path,
		})
	})

	httpServer := server.New(server.Options{
		Addr:         ":8081",
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
