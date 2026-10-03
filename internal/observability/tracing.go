package observability

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/stats"
)

type Tracing struct {
	enabled    bool
	provider   trace.TracerProvider
	sdk        *sdktrace.TracerProvider
	tracer     trace.Tracer
	propagator propagation.TraceContext
}

// NewTracing does not create an exporter or goroutines when tracing is disabled.
// Tests may inject an in-memory SpanExporter without opening a network socket.
func NewTracing(ctx context.Context, options Options, version string, exporter sdktrace.SpanExporter) (*Tracing, error) {
	if !options.Tracing.Enabled {
		p := noop.NewTracerProvider()
		return &Tracing{provider: p, tracer: p.Tracer("aegisgate")}, nil
	}
	if exporter == nil {
		var err error
		endpoint := strings.TrimRight(options.Tracing.Endpoint, "/") + "/v1/traces"
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint), otlptracehttp.WithTimeout(options.Tracing.ExportTimeout))
		if err != nil {
			return nil, err
		}
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", options.ServiceName),
		attribute.String("service.version", version),
		attribute.String("deployment.environment", options.Environment),
	)
	p := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(options.Tracing.SampleRatio))),
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(options.Tracing.BatchTimeout),
			sdktrace.WithExportTimeout(options.Tracing.ExportTimeout),
			sdktrace.WithMaxQueueSize(options.Tracing.MaxQueueSize),
			sdktrace.WithMaxExportBatchSize(options.Tracing.MaxExportBatchSize)),
	)
	return &Tracing{enabled: true, provider: p, sdk: p, tracer: p.Tracer("aegisgate"), propagator: propagation.TraceContext{}}, nil
}

func (t *Tracing) Enabled() bool { return t != nil && t.enabled }

// GRPCClientHandler and GRPCServerHandler use this process's explicit provider
// and trace-context propagator, never the global OpenTelemetry configuration.
func (t *Tracing) GRPCClientHandler() stats.Handler {
	if !t.Enabled() {
		return nil
	}
	return otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(t.provider), otelgrpc.WithPropagators(t.propagator), otelgrpc.WithMeterProvider(metricnoop.NewMeterProvider()))
}

func (t *Tracing) GRPCServerHandler() stats.Handler {
	if !t.Enabled() {
		return nil
	}
	return otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(t.provider), otelgrpc.WithPropagators(t.propagator), otelgrpc.WithMeterProvider(metricnoop.NewMeterProvider()))
}

func (t *Tracing) StartServer(r *http.Request) (context.Context, trace.Span) {
	ctx := t.propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	return t.tracer.Start(ctx, "gateway.request", trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("http.request.method", metricMethod(r.Method))))
}

func (t *Tracing) StartCheck(ctx context.Context, name string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal))
}

func (t *Tracing) StartUpstream(ctx context.Context, route, host string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, "upstream.request", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("aegisgate.route.id", metricRoute(route)), attribute.String("server.address", host)))
}

func (t *Tracing) Inject(ctx context.Context, header http.Header) {
	header.Del("traceparent")
	header.Del("tracestate")
	header.Del("baggage")
	if t != nil && t.enabled {
		// Keep the trace/span identity, but do not relay client-controlled
		// tracestate vendor entries across the gateway trust boundary.
		if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
			ctx = trace.ContextWithSpanContext(ctx, spanContext.WithTraceState(trace.TraceState{}))
		}
		t.propagator.Inject(ctx, propagation.HeaderCarrier(header))
	}
}

func (t *Tracing) Shutdown(ctx context.Context) error {
	if t == nil || t.sdk == nil {
		return nil
	}
	return t.sdk.Shutdown(ctx)
}

func (t *Tracing) ForceFlush(ctx context.Context) error {
	if t == nil || t.sdk == nil {
		return nil
	}
	return t.sdk.ForceFlush(ctx)
}

func SetRoute(ctx context.Context, route, pattern string) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}
	span.SetName("gateway " + pattern)
	span.SetAttributes(attribute.String("aegisgate.route.id", metricRoute(route)))
}
func SetDecision(ctx context.Context, key, value string) {
	if !trace.SpanFromContext(ctx).SpanContext().IsValid() {
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.String(key, value))
}
func SetOutcome(ctx context.Context, outcome string, status int) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}
	span.SetAttributes(attribute.String("aegisgate.outcome", metricOutcome(outcome)), attribute.Int("http.response.status_code", status))
	if outcome == OutcomeUpstreamTimeout || outcome == OutcomeUpstreamError || outcome == OutcomeInternalError || outcome == OutcomeDependencyUnavailable {
		span.SetStatus(codes.Error, outcome)
	}
}
func TraceIDs(ctx context.Context) (string, string) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}
