package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type discardExporter struct{}

func (discardExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (discardExporter) Shutdown(context.Context) error                             { return nil }

func BenchmarkRequestInstrumentation(b *testing.B) {
	for _, mode := range []string{"disabled", "metrics", "tracing_unsampled", "tracing_sampled"} {
		b.Run(mode, func(b *testing.B) {
			var metrics *Metrics
			var tracing *Tracing
			if mode == "metrics" {
				metrics = NewMetrics("bench", "unknown", "unknown", nil)
			}
			if mode == "tracing_unsampled" || mode == "tracing_sampled" {
				ratio := 0.0
				if mode == "tracing_sampled" {
					ratio = 1
				}
				options := testTracingOptions(ratio)
				options.Tracing.BatchTimeout = time.Second
				var err error
				tracing, err = NewTracing(context.Background(), options, "bench", discardExporter{})
				if err != nil {
					b.Fatal(err)
				}
				defer tracing.Shutdown(context.Background())
			}
			handler := Middleware(tracing, metrics, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				SetRequestRoute(r.Context(), "users", "/api/users")
				if metrics != nil {
					metrics.EndRequest("users", "GET", OutcomeSuccess, 200, time.Microsecond)
				}
				w.WriteHeader(200)
			}))
			request := httptest.NewRequest("GET", "http://gateway.local/api/users/42", nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				handler.ServeHTTP(httptest.NewRecorder(), request)
			}
		})
	}
}

func BenchmarkSecurityEventSnapshotCollector(b *testing.B) {
	collector := newPipelineCollector(fixedSnapshot{securityevent.Snapshot{AcceptedTotal: 4, IngressQueueDepth: 2}})
	metrics := NewMetrics("bench", "unknown", "unknown", nil)
	metrics.Registry().MustRegister(collector)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := metrics.Registry().Gather(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUpstreamPropagation(b *testing.B) {
	options := testTracingOptions(1)
	tracing, err := NewTracing(context.Background(), options, "bench", discardExporter{})
	if err != nil {
		b.Fatal(err)
	}
	defer tracing.Shutdown(context.Background())
	ctx, span := tracing.StartServer(httptest.NewRequest("GET", "/", nil))
	defer span.End()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		tracing.Inject(ctx, header)
	}
}
