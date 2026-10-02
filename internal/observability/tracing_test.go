package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type failedExporter struct{}

func (failedExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return errors.New("collector unavailable")
}
func (failedExporter) Shutdown(context.Context) error { return nil }

type blockingExporter struct{ started chan struct{} }

func (e blockingExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	select {
	case e.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func (blockingExporter) Shutdown(context.Context) error { return nil }

func testTracingOptions(ratio float64) Options {
	return Options{ServiceName: "aegisgate", Environment: "test", Tracing: TracingOptions{
		Enabled: true, Endpoint: "http://localhost:4318", SampleRatio: ratio,
		ExportTimeout: time.Second, BatchTimeout: time.Hour, MaxQueueSize: 32,
		MaxExportBatchSize: 8, ShutdownTimeout: time.Second,
	}}
}

func TestTracingInboundPropagationRouteAndDecisions(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tracing, err := NewTracing(context.Background(), testTracingOptions(1), "test", exporter)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://gateway.local/api/users/secret?q=credential", nil)
	request.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	request.Header.Set("baggage", "password=do-not-export")
	request.Header.Set("tracestate", "vendor=okay")
	request = request.WithContext(context.WithValue(request.Context(), requestStateKey{}, &RequestState{Outcome: OutcomeSuccess}))
	ctx, serverSpan := tracing.StartServer(request)
	SetRequestRoute(ctx, "users", "/api/users")
	SetDecision(ctx, "aegisgate.auth.outcome", "unauthorized")
	SetOutcome(ctx, OutcomeUnauthorized, http.StatusUnauthorized)
	upstreamCtx, upstreamSpan := tracing.StartUpstream(ctx, "users", "users-upstream")
	upstreamHeader := http.Header{"Baggage": []string{"password=do-not-export"}}
	tracing.Inject(upstreamCtx, upstreamHeader)
	if upstreamHeader.Get("traceparent") == "" || upstreamHeader.Get("baggage") != "" || upstreamHeader.Get("tracestate") != "" {
		t.Fatal(upstreamHeader)
	}
	upstreamSpan.End()
	serverSpan.End()
	if err := tracing.sdk.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("spans=%d", len(spans))
	}
	for _, span := range spans {
		if span.Name == "gateway /api/users" {
			if span.Parent.TraceID().String() != "0123456789abcdef0123456789abcdef" || span.Status.Code == codes.Error {
				t.Fatalf("server span parent/status: %#v", span)
			}
		}
		for _, attr := range span.Attributes {
			if attr.Key == "url.full" || attr.Key == "http.target" || attr.Key == "client.id" || attr.Key == "client.address" || attr.Key == "baggage" {
				t.Fatalf("sensitive attribute %s", attr.Key)
			}
		}
	}
	if err := tracing.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTracingInvalidHeaderAndDisabled(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tracing, err := NewTracing(context.Background(), testTracingOptions(1), "test", exporter)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/private", nil)
	request.Header.Set("traceparent", "invalid")
	ctx, span := tracing.StartServer(request)
	if !span.SpanContext().IsValid() || span.SpanContext().TraceID().String() == "invalid" {
		t.Fatal("invalid inbound header accepted")
	}
	span.End()
	_ = ctx
	if err := tracing.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	disabled, err := NewTracing(context.Background(), Options{}, "dev", nil)
	if err != nil || disabled.Enabled() {
		t.Fatalf("disabled tracing: %v", err)
	}
	if err := disabled.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExporterFailureDoesNotChangeHTTPResponse(t *testing.T) {
	options := testTracingOptions(1)
	options.Tracing.BatchTimeout = time.Millisecond
	tracing, err := NewTracing(context.Background(), options, "test", failedExporter{})
	if err != nil {
		t.Fatal(err)
	}
	handler := Middleware(tracing, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRequestRoute(r.Context(), "users", "/api/users")
		w.WriteHeader(http.StatusAccepted)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
	if response.Code != http.StatusAccepted {
		t.Fatal(response.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tracing.Shutdown(ctx)
}

func TestTracingShutdownIsBoundedWhenExporterStalls(t *testing.T) {
	options := testTracingOptions(1)
	options.Tracing.MaxExportBatchSize = 1
	options.Tracing.ExportTimeout = 100 * time.Millisecond
	exporter := blockingExporter{started: make(chan struct{}, 1)}
	tracing, err := NewTracing(context.Background(), options, "test", exporter)
	if err != nil {
		t.Fatal(err)
	}
	_, span := tracing.StartServer(httptest.NewRequest("GET", "/", nil))
	span.End()
	select {
	case <-exporter.started:
	case <-time.After(time.Second):
		t.Fatal("export did not start")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = tracing.Shutdown(ctx)
	if time.Since(started) > 300*time.Millisecond {
		t.Fatal("shutdown exceeded configured bound")
	}
}
