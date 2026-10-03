package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/controlplane"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/Nuryanfa/AegisGate/internal/proxy"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/Nuryanfa/AegisGate/internal/server"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
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
	var eventPipeline *securityevent.Pipeline
	if cfg.SecurityEvents != nil {
		sink, err := securityevent.NewSlogSink(logger)
		if err != nil {
			logger.Error("build security-event sink", "error", err)
			os.Exit(1)
		}
		eventPipeline, err = securityevent.NewPipeline(*cfg.SecurityEvents, sink, logger, nil)
		if err != nil {
			logger.Error("build security-event pipeline", "error", err)
			os.Exit(1)
		}
	}
	var metrics *observability.Metrics
	var tracing *observability.Tracing
	if cfg.Observability != nil {
		if cfg.Observability.Metrics.Enabled {
			metrics = newBuildMetrics(eventPipeline)
		}
		if cfg.Observability.Tracing.Enabled {
			tracing, err = observability.NewTracing(context.Background(), *cfg.Observability, version, nil)
			if err != nil {
				shutdownSecurityEvents(eventPipeline, cfg.SecurityEvents, logger)
				logger.Error("initialize tracing", "error", err)
				os.Exit(1)
			}
		}
	}
	proxyHandler, err := proxy.NewWithObservability(cfg.Routes, registry, limiter, waf.NewEngine(), eventPipeline, metrics, tracing, logger)
	if err != nil {
		shutdownSecurityEvents(eventPipeline, cfg.SecurityEvents, logger)
		shutdownTracing(tracing, cfg.Observability, logger)
		logger.Error("build gateway routes", "error", err)
		os.Exit(1)
	}
	var runtimeStore *controlplane.Store
	var syncClient *controlplane.Client
	if cfg.ControlPlane != nil {
		bootstrap := config.Bootstrap(cfg)
		wire, wireErr := controlplane.ToProto(bootstrap)
		if wireErr != nil {
			logger.Error("invalid bootstrap snapshot", "reason", "validation")
			os.Exit(1)
		}
		revision, revErr := controlplane.Revision(wire)
		if revErr != nil {
			logger.Error("invalid bootstrap revision", "reason", "validation")
			os.Exit(1)
		}
		compiler := controlplane.Compiler{WriteTimeout: cfg.WriteTimeout, Limiter: limiter, Inspector: waf.NewEngine(), Events: eventPipeline, Metrics: metrics, Tracing: tracing, Logger: logger}
		runtimeStore = controlplane.NewStore(&controlplane.Runtime{Revision: revision, Handler: proxyHandler, Routes: cfg.Routes}, compiler, cfg.ControlPlane)
		syncClient, err = controlplane.NewClient(*cfg.ControlPlane, runtimeStore, logger)
		if err != nil {
			logger.Error("invalid control-plane client credentials", "reason", "validation")
			os.Exit(1)
		}
		if metrics != nil {
			cpMetrics := observability.NewControlPlaneMetrics(metrics.Registry())
			runtimeStore.SetMetrics(cpMetrics)
			syncClient.SetMetrics(cpMetrics)
		}
		syncClient.SetTracing(tracing)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.HealthHandler)
	readinessChecks := make([]server.ReadinessCheck, 0, 1)
	if limiter != nil {
		readinessChecks = append(readinessChecks, func(ctx context.Context) error {
			routes := cfg.Routes
			if runtimeStore != nil {
				routes = runtimeStore.Active().Routes
			}
			if hasFailClosedRateLimit(routes) {
				return limiter.Ping(ctx)
			}
			return nil
		})
	}
	if runtimeStore != nil {
		readinessChecks = append(readinessChecks, func(context.Context) error {
			if runtimeStore.Ready() {
				return nil
			}
			return errors.New("control-plane configuration unavailable")
		})
	}
	mux.Handle("/readyz", server.ReadinessHandler(readinessChecks...))
	if runtimeStore != nil {
		mux.Handle("/", runtimeStore)
	} else {
		mux.Handle("/", proxyHandler)
	}

	handler := middleware.RequestID(observability.Middleware(tracing, metrics, middleware.LoggingWithObservability(logger, mux, metrics)))
	httpServer := server.New(server.Options{
		Addr:         cfg.HTTPAddr,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}, handler, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var syncDone chan struct{}
	if syncClient != nil {
		syncDone = make(chan struct{})
		go func() { defer close(syncDone); syncClient.Run(ctx) }()
	}
	var telemetry *server.Telemetry
	if metrics != nil {
		telemetry, err = server.StartTelemetry(cfg.Observability.Metrics, metrics.Handler(cfg.Observability.Metrics.Path), logger)
		if err != nil {
			shutdownSecurityEvents(eventPipeline, cfg.SecurityEvents, logger)
			shutdownTracing(tracing, cfg.Observability, logger)
			logger.Error("start telemetry server", "error", err)
			os.Exit(1)
		}
	}

	logStartup(logger, cfg, eventPipeline, metrics, tracing)
	telemetryTimeout := time.Second
	if telemetry != nil {
		telemetryTimeout = cfg.Observability.Metrics.ShutdownTimeout
	}
	runErr := server.RunWithTelemetry(ctx, httpServer, telemetry, cfg.ShutdownTimeout, telemetryTimeout)
	if syncDone != nil {
		stop()
		select {
		case <-syncDone:
		case <-time.After(cfg.ControlPlane.ShutdownTimeout):
			logger.Warn("control-plane client shutdown deadline reached")
		}
	}
	shutdownSecurityEvents(eventPipeline, cfg.SecurityEvents, logger)
	shutdownTracing(tracing, cfg.Observability, logger)
	if runErr != nil {
		logger.Error("gateway stopped with an error", "error", runErr)
		os.Exit(1)
	}
}

func newBuildMetrics(pipeline observability.SnapshotSource) *observability.Metrics {
	return observability.NewMetrics(version, commit, buildTime, pipeline)
}

func logStartup(logger *slog.Logger, cfg config.Config, eventPipeline *securityevent.Pipeline, metrics *observability.Metrics, tracing *observability.Tracing) {
	logger.Info("AegisGate initialized",
		"environment", cfg.Environment,
		"route_count", len(cfg.Routes),
		"api_key_count", len(cfg.APIKeys),
		"rate_limited_route_count", rateLimitedRouteCount(cfg.Routes),
		"waf_enabled_route_count", wafEnabledRouteCount(cfg.Routes),
		"security_event_pipeline_enabled", eventPipeline != nil,
		"metrics_enabled", metrics != nil,
		"tracing_enabled", tracing != nil,
		"version", version, "commit", commit, "build_time", buildTime,
	)
}

func shutdownTracing(tracing *observability.Tracing, options *observability.Options, logger *slog.Logger) {
	if tracing == nil || options == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.Tracing.ShutdownTimeout)
	defer cancel()
	if err := tracing.Shutdown(ctx); err != nil {
		logger.Warn("tracing shutdown deadline reached")
	}
}

func shutdownSecurityEvents(pipeline *securityevent.Pipeline, options *securityevent.Options, logger *slog.Logger) {
	if pipeline == nil || options == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.ShutdownTimeout)
	defer cancel()
	if err := pipeline.Shutdown(ctx); err != nil {
		logger.Warn("security-event pipeline shutdown deadline reached")
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
