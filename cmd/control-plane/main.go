package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/controlplane"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	path := os.Getenv("AEGIS_CONTROL_PLANE_CONFIG_PATH")
	if path == "" {
		logger.Error("AEGIS_CONTROL_PLANE_CONFIG_PATH is required")
		os.Exit(1)
	}
	settings, err := controlplane.LoadServerConfig(path)
	if err != nil {
		logger.Error("invalid control-plane configuration", "reason", "validation")
		os.Exit(1)
	}
	initial, err := config.ReadDynamic(settings.SnapshotFile)
	if err != nil {
		logger.Error("invalid initial snapshot", "reason", "validation")
		os.Exit(1)
	}
	service, err := controlplane.NewServer(initial, settings.MaxClients, logger)
	if err != nil {
		logger.Error("invalid initial snapshot", "reason", "validation")
		os.Exit(1)
	}
	if err := service.SetMessageLimit(settings.MaxMessageBytes); err != nil {
		logger.Error("initial snapshot exceeds message limit", "reason", "capacity")
		os.Exit(1)
	}
	registry := prometheus.NewRegistry()
	cpMetrics := observability.NewControlPlaneMetrics(registry)
	service.SetMetrics(cpMetrics)
	var tracing *observability.Tracing
	shutdownTracing := func() {
		if tracing == nil {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracing.Shutdown(shutdownCtx)
	}
	if settings.TracingEndpoint != "" {
		traceOptions := observability.Options{ServiceName: "aegisgate-control-plane", Environment: settings.Environment, Tracing: observability.TracingOptions{Enabled: true, Endpoint: settings.TracingEndpoint, SampleRatio: 1, ExportTimeout: 2 * time.Second, BatchTimeout: 5 * time.Second, MaxQueueSize: 2048, MaxExportBatchSize: 512, ShutdownTimeout: 5 * time.Second}}
		if err := traceOptions.Validate(); err != nil {
			logger.Error("invalid tracing configuration", "reason", "validation")
			os.Exit(1)
		}
		tracing, err = observability.NewTracing(context.Background(), traceOptions, "dev", nil)
		if err != nil {
			logger.Error("tracing initialization failed", "reason", "dependency")
			os.Exit(1)
		}
		service.SetTracing(tracing)
		defer shutdownTracing()
	}
	var metricsServer *http.Server
	var metricsServeErr <-chan error
	if settings.MetricsAddress != "" {
		metricsListener, err := net.Listen("tcp", settings.MetricsAddress)
		if err != nil {
			logger.Error("metrics listener unavailable", "reason", "dependency")
			shutdownTracing()
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		metricsServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
		errors := make(chan error, 1)
		metricsServeErr = errors
		go func() { errors <- metricsServer.Serve(metricsListener) }()
	}
	listener, err := net.Listen("tcp", settings.Address)
	if err != nil {
		logger.Error("control-plane listener unavailable", "reason", "dependency")
		shutdownTracing()
		os.Exit(1)
	}
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(settings.MaxMessageBytes), grpc.MaxSendMsgSize(settings.MaxMessageBytes), grpc.MaxConcurrentStreams(uint32(settings.MaxClients)),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 15 * time.Second, PermitWithoutStream: false}),
	}
	if tracing != nil && tracing.Enabled() {
		options = append(options, grpc.StatsHandler(tracing.GRPCServerHandler()))
	}
	if settings.TLS.Enabled {
		creds, err := controlplane.ServerCredentials(settings.TLS)
		if err != nil {
			logger.Error("invalid TLS credentials", "reason", "validation")
			shutdownTracing()
			os.Exit(1)
		}
		options = append(options, grpc.Creds(creds))
	} else {
		logger.Warn("insecure gRPC enabled; development only")
	}
	grpcServer := grpc.NewServer(options...)
	cpb.RegisterConfigurationServiceServer(grpcServer, service)
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(controlplane.LimitListener(listener, settings.MaxClients)) }()
	logger.Info("control plane serving", "revision", service.Revision())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-hup:
			changed, err := service.Reload(settings.SnapshotFile)
			if err != nil {
				logger.Warn("snapshot reload rejected", "reason", "validation")
				cpMetrics.ObserveReload("rejected")
				continue
			}
			if changed {
				cpMetrics.ObserveReload("success")
				logger.Info("snapshot published", "revision", service.Revision())
			} else {
				cpMetrics.ObserveReload("unchanged")
				logger.Info("snapshot unchanged", "revision", service.Revision())
			}
		case <-ctx.Done():
			shutdownServers(grpcServer, metricsServer, healthServer, settings.ShutdownTimeout)
			logger.Info("control plane stopped")
			return
		case err := <-metricsServeErr:
			if err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server failed", "reason", "dependency")
				shutdownServers(grpcServer, metricsServer, healthServer, settings.ShutdownTimeout)
				shutdownTracing()
				os.Exit(1)
			}
			metricsServeErr = nil
		case err := <-serveErr:
			if err != nil {
				logger.Error("control-plane server failed", "reason", "dependency")
				shutdownServers(grpcServer, metricsServer, healthServer, settings.ShutdownTimeout)
				shutdownTracing()
				os.Exit(1)
			}
			return
		}
	}
}

func shutdownServers(grpcServer *grpc.Server, metricsServer *http.Server, healthServer *health.Server, timeout time.Duration) {
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	if metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = metricsServer.Shutdown(ctx)
		cancel()
	}
	finished := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(timeout):
		grpcServer.Stop()
		<-finished
	}
}
