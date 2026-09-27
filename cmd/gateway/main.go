package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/proxy"
	"github.com/Nuryanfa/AegisGate/internal/server"
)

func main() {
	bootstrapLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("configuration is invalid", "error", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Environment)
	proxyHandler, err := proxy.New(cfg.Routes, logger)
	if err != nil {
		logger.Error("build gateway routes", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.HealthHandler)
	mux.Handle("/readyz", server.ReadinessHandler())
	mux.Handle("/", proxyHandler)

	handler := middleware.RequestID(middleware.Logging(logger, mux))
	httpServer := server.New(server.Options{
		Addr:         cfg.HTTPAddr,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}, handler, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("AegisGate initialized",
		"environment", cfg.Environment,
		"route_count", len(cfg.Routes),
	)
	if err := httpServer.Run(ctx, cfg.ShutdownTimeout); err != nil {
		logger.Error("gateway stopped with an error", "error", err)
		os.Exit(1)
	}
}

func newLogger(environment string) *slog.Logger {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if environment == "development" {
		return slog.New(slog.NewTextHandler(os.Stdout, options))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, options))
}
