package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/proxy"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/server"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

func main() {
	bootstrapLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("configuration is invalid", "error", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Environment)
	registry, err := auth.NewRegistry(cfg.APIKeys)
	if err != nil {
		logger.Error("build API key registry", "error", err)
		os.Exit(1)
	}
	var limiter *ratelimit.RedisLimiter
	if cfg.Redis != nil {
		limiter, err = ratelimit.NewRedisLimiter(ratelimit.RedisOptions{
			Address:        cfg.Redis.Address,
			Username:       cfg.Redis.Username,
			Password:       cfg.Redis.Password,
			Database:       cfg.Redis.Database,
			ConnectTimeout: cfg.Redis.ConnectTimeout,
			CommandTimeout: cfg.Redis.CommandTimeout,
			PoolSize:       cfg.Redis.PoolSize,
		})
		if err != nil {
			logger.Error("build Redis rate limiter", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := limiter.Close(); err != nil {
				logger.Warn("close Redis client", "error", err)
			}
		}()
	}
	proxyHandler, err := proxy.NewWithPolicies(cfg.Routes, registry, limiter, waf.NewEngine(), logger)
	if err != nil {
		logger.Error("build gateway routes", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.HealthHandler)
	readinessChecks := make([]server.ReadinessCheck, 0, 1)
	if limiter != nil && hasFailClosedRateLimit(cfg.Routes) {
		readinessChecks = append(readinessChecks, limiter.Ping)
	}
	mux.Handle("/readyz", server.ReadinessHandler(readinessChecks...))
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
		"api_key_count", len(cfg.APIKeys),
		"rate_limited_route_count", rateLimitedRouteCount(cfg.Routes),
		"waf_enabled_route_count", wafEnabledRouteCount(cfg.Routes),
	)
	if err := httpServer.Run(ctx, cfg.ShutdownTimeout); err != nil {
		logger.Error("gateway stopped with an error", "error", err)
		os.Exit(1)
	}
}

func wafEnabledRouteCount(routes []router.Route) int {
	count := 0
	for _, route := range routes {
		if route.WAF != nil && route.WAF.Enabled() {
			count++
		}
	}
	return count
}

func hasFailClosedRateLimit(routes []router.Route) bool {
	for _, route := range routes {
		if route.RateLimit != nil && route.RateLimit.FailClosed() {
			return true
		}
	}
	return false
}

func rateLimitedRouteCount(routes []router.Route) int {
	count := 0
	for _, route := range routes {
		if route.RateLimit != nil {
			count++
		}
	}
	return count
}

func newLogger(environment string) *slog.Logger {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if environment == "development" {
		return slog.New(slog.NewTextHandler(os.Stdout, options))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, options))
}
