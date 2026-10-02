package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/waf"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestProxyObservabilityAndPolicyClassification(t *testing.T) {
	upstreamHeaders := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	exporter := tracetest.NewInMemoryExporter()
	options := observability.Options{ServiceName: "aegisgate", Environment: "test", Tracing: observability.TracingOptions{
		Enabled: true, Endpoint: "http://localhost:4318", SampleRatio: 1,
		ExportTimeout: time.Second, BatchTimeout: 10 * time.Millisecond, MaxQueueSize: 32,
		MaxExportBatchSize: 8, ShutdownTimeout: time.Second,
	}}
	tracing, err := observability.NewTracing(context.Background(), options, "test", exporter)
	if err != nil {
		t.Fatal(err)
	}
	defer tracing.Shutdown(context.Background())
	metrics := observability.NewMetrics("test", "unknown", "unknown", nil)
	route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
	ratePolicy := rateLimitPolicy(t, 5, 1, "deny")
	route.RateLimit = &ratePolicy
	wafPolicy := proxyWAFPolicy(t, "enforce", 5, false)
	route.WAF = &wafPolicy
	limiter := &stubRateLimiter{decision: ratelimit.Decision{Allowed: true}}
	inspector := &stubInspector{result: waf.Result{Action: waf.ActionAllow}}
	handler, err := NewWithObservability([]router.Route{route}, emptyRegistry(t), limiter, inspector, &stubSecurityEventPublisher{accept: true}, metrics, tracing, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := middleware.RequestID(observability.Middleware(tracing, metrics, middleware.LoggingWithObservability(discardLogger(), handler, metrics)))
	request := httptest.NewRequest("GET", "http://gateway.local/api/users/private?q=secret", nil)
	request.RemoteAddr = "203.0.113.1:1234"
	request.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	request.Header.Set("baggage", "secret=do-not-forward")
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	select {
	case header := <-upstreamHeaders:
		if header.Get("traceparent") == "" || header.Get("baggage") != "" {
			t.Fatalf("upstream headers: %v", header)
		}
	default:
		t.Fatal("upstream not reached")
	}

	inspector.result = waf.Result{Action: waf.ActionBlock}
	blocked := httptest.NewRecorder()
	wrapped.ServeHTTP(blocked, httptest.NewRequest("GET", "http://gateway.local/api/users/blocked", nil))
	if blocked.Code != 403 {
		t.Fatal(blocked.Code)
	}
	privateRoute := route
	privateRoute.Auth = protectedPolicy(t, "read")
	privateHandler, err := NewWithObservability([]router.Route{privateRoute}, emptyRegistry(t), limiter, inspector, &stubSecurityEventPublisher{accept: true}, metrics, tracing, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := middleware.RequestID(observability.Middleware(tracing, metrics, middleware.LoggingWithObservability(discardLogger(), privateHandler, metrics)))
	denied := httptest.NewRecorder()
	unauthorized.ServeHTTP(denied, httptest.NewRequest("GET", "http://gateway.local/api/users/denied", nil))
	if denied.Code != 401 {
		t.Fatal(denied.Code)
	}

	scrape := httptest.NewRecorder()
	metrics.Handler("/metrics").ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
	body := scrape.Body.String()
	for _, label := range []string{"outcome=\"success\"", "outcome=\"waf_blocked\"", "outcome=\"unauthorized\""} {
		if !strings.Contains(body, label) {
			t.Fatalf("missing %q", label)
		}
	}
	for _, secret := range []string{"/api/users/private", "do-not-forward", "203.0.113.1"} {
		if strings.Contains(body, secret) {
			t.Fatalf("metric leak: %q", secret)
		}
	}
	deadline := time.After(time.Second)
	for len(exporter.GetSpans()) < 7 {
		select {
		case <-deadline:
			t.Fatalf("spans=%d", len(exporter.GetSpans()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	foundWAF, foundRate, foundPolicy := false, false, false
	for _, span := range exporter.GetSpans() {
		switch span.Name {
		case "waf.inspect":
			foundWAF = true
		case "rate_limit.check":
			foundRate = true
		case "gateway /api/users":
			if span.Status.Code != codes.Error {
				foundPolicy = true
			}
		}
	}
	if !foundWAF || !foundRate || !foundPolicy {
		t.Fatalf("missing spans: waf=%t rate=%t policy=%t", foundWAF, foundRate, foundPolicy)
	}
}

func TestProxySanitizesTraceAndSecurityHeadersWithTracingDisabledOrEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			observed := make(chan http.Header, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			var tracing *observability.Tracing
			if enabled {
				options := observability.Options{ServiceName: "aegisgate", Environment: "test", Tracing: observability.TracingOptions{
					Enabled: true, Endpoint: "http://localhost:4318", SampleRatio: 1,
					ExportTimeout: time.Second, BatchTimeout: time.Second, MaxQueueSize: 32,
					MaxExportBatchSize: 8, ShutdownTimeout: time.Second,
				}}
				var err error
				tracing, err = observability.NewTracing(context.Background(), options, "test", tracetest.NewInMemoryExporter())
				if err != nil {
					t.Fatal(err)
				}
				defer tracing.Shutdown(context.Background())
			}
			handler, err := NewWithObservability([]router.Route{publicRoute(t, "users", "/api/users", upstream.URL, time.Second)}, emptyRegistry(t), nil, nil, nil, nil, tracing, discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			wrapped := middleware.RequestID(observability.Middleware(tracing, nil, handler))
			request := httptest.NewRequest(http.MethodGet, "http://gateway.local/api/users/42", nil)
			request.RemoteAddr = "203.0.113.2:4321"
			inboundParent := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
			request.Header.Set("traceparent", inboundParent)
			request.Header.Set("tracestate", "vendor=example")
			request.Header.Set("baggage", "secret=arbitrary-client-value")
			request.Header.Set("X-Forwarded-For", "198.51.100.99")
			request.Header.Set("Forwarded", "for=198.51.100.99")
			request.Header.Set("X-Real-IP", "198.51.100.99")
			request.Header.Set("X-API-Key", "credential")
			request.Header.Set("X-Aegis-Client-ID", "spoofed")
			response := httptest.NewRecorder()
			wrapped.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatal(response.Code)
			}
			var header http.Header
			select {
			case header = <-observed:
			default:
				t.Fatal("upstream not reached")
			}
			for _, key := range []string{"baggage", "Forwarded", "X-Real-IP", "X-API-Key", "X-Aegis-Client-ID"} {
				if got := header.Get(key); got != "" {
					t.Fatalf("%s leaked: %q", key, got)
				}
			}
			if got := header.Get("X-Forwarded-For"); got != "203.0.113.2" {
				t.Fatalf("forwarded peer = %q", got)
			}
			if got := header.Get(middleware.RequestIDHeader); got == "" {
				t.Fatal("request ID missing")
			}
			if !enabled {
				for _, key := range []string{"traceparent", "tracestate"} {
					if got := header.Get(key); got != "" {
						t.Fatalf("%s leaked with tracing off: %q", key, got)
					}
				}
				return
			}
			outboundParent := header.Get("traceparent")
			if outboundParent == "" || outboundParent == inboundParent || !strings.Contains(outboundParent, "0123456789abcdef0123456789abcdef") {
				t.Fatalf("invalid AegisGate-controlled traceparent: %q", outboundParent)
			}
			if got := header.Get("tracestate"); got != "" {
				t.Fatalf("client tracestate leaked: %q", got)
			}
		})
	}
}

func TestProxyObservabilityRecordsUpstreamFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	address := upstream.URL
	upstream.Close()
	exporter := tracetest.NewInMemoryExporter()
	options := observability.Options{ServiceName: "aegisgate", Environment: "test", Tracing: observability.TracingOptions{
		Enabled: true, Endpoint: "http://localhost:4318", SampleRatio: 1,
		ExportTimeout: time.Second, BatchTimeout: time.Millisecond, MaxQueueSize: 32,
		MaxExportBatchSize: 1, ShutdownTimeout: time.Second,
	}}
	tracing, err := observability.NewTracing(context.Background(), options, "test", exporter)
	if err != nil {
		t.Fatal(err)
	}
	defer tracing.Shutdown(context.Background())
	metrics := observability.NewMetrics("test", "unknown", "unknown", nil)
	handler, err := NewWithObservability([]router.Route{publicRoute(t, "users", "/api/users", address, time.Second)}, emptyRegistry(t), nil, nil, nil, metrics, tracing, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := middleware.RequestID(observability.Middleware(tracing, metrics, middleware.LoggingWithObservability(discardLogger(), handler, metrics)))
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, httptest.NewRequest("GET", "http://gateway.local/api/users/42", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatal(response.Code)
	}
	scrape := httptest.NewRecorder()
	metrics.Handler("/metrics").ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `outcome="upstream_error"`) || !strings.Contains(scrape.Body.String(), `result="error"`) {
		t.Fatal("missing upstream error metrics")
	}
	deadline := time.After(time.Second)
	for {
		for _, span := range exporter.GetSpans() {
			if span.Name == "upstream.request" && span.Status.Code == codes.Error {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatal("missing upstream error span")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestProxyObservabilityRecordsUpstreamTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer upstream.Close()
	metrics := observability.NewMetrics("test", "unknown", "unknown", nil)
	handler, err := NewWithObservability([]router.Route{publicRoute(t, "users", "/api/users", upstream.URL, 20*time.Millisecond)}, emptyRegistry(t), nil, nil, nil, metrics, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := middleware.RequestID(observability.Middleware(nil, metrics, middleware.LoggingWithObservability(discardLogger(), handler, metrics)))
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, httptest.NewRequest("GET", "http://gateway.local/api/users/42", nil))
	if response.Code != http.StatusGatewayTimeout {
		t.Fatal(response.Code)
	}
	scrape := httptest.NewRecorder()
	metrics.Handler("/metrics").ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `outcome="upstream_timeout"`) || !strings.Contains(scrape.Body.String(), `result="timeout"`) {
		t.Fatal("missing upstream timeout metrics")
	}
}
