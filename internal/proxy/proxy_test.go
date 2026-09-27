package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/router"
)

func TestProxyForwardsRequestAndResponse(t *testing.T) {
	type observedRequest struct {
		path           string
		requestID      string
		forwardedFor   string
		forwardedHost  string
		forwardedProto string
		forwardedPort  string
		host           string
	}
	observed := make(chan observedRequest, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- observedRequest{
			path:           r.URL.Path,
			requestID:      r.Header.Get(middleware.RequestIDHeader),
			forwardedFor:   r.Header.Get("X-Forwarded-For"),
			forwardedHost:  r.Header.Get("X-Forwarded-Host"),
			forwardedProto: r.Header.Get("X-Forwarded-Proto"),
			forwardedPort:  r.Header.Get("X-Forwarded-Port"),
			host:           r.Host,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"service":"test-upstream"}`)
	}))
	defer upstream.Close()

	handler, err := New([]router.Route{{
		ID: "test", PathPrefix: "/api/test", Upstream: upstream.URL, Timeout: time.Second,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handlerWithRequestID := middleware.RequestID(handler)

	request := httptest.NewRequest(http.MethodGet, "http://gateway.local/api/test/hello", nil)
	request.Host = "public.example"
	request.RemoteAddr = "203.0.113.10:54321"
	request.Header.Set(middleware.RequestIDHeader, "request-123")
	request.Header.Set("X-Forwarded-For", "198.51.100.99")
	request.Header.Set("X-Forwarded-Port", "4444")
	response := httptest.NewRecorder()

	handlerWithRequestID.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
	}
	if got := response.Header().Get(middleware.RequestIDHeader); got != "request-123" {
		t.Fatalf("response request ID = %q, want request-123", got)
	}
	if got := response.Header().Values(middleware.RequestIDHeader); len(got) != 1 {
		t.Fatalf("response request ID values = %v, want exactly one value", got)
	}

	got := <-observed
	if got.path != "/api/test/hello" {
		t.Errorf("upstream path = %q, want /api/test/hello", got.path)
	}
	if got.requestID != "request-123" {
		t.Errorf("upstream request ID = %q, want request-123", got.requestID)
	}
	if got.forwardedFor != "203.0.113.10" {
		t.Errorf("X-Forwarded-For = %q, want connection IP only", got.forwardedFor)
	}
	if got.forwardedHost != "public.example" {
		t.Errorf("X-Forwarded-Host = %q, want public.example", got.forwardedHost)
	}
	if got.forwardedProto != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", got.forwardedProto)
	}
	if got.forwardedPort != "" {
		t.Errorf("X-Forwarded-Port = %q, want client value removed", got.forwardedPort)
	}
	if got.host == "public.example" {
		t.Errorf("upstream Host = %q, must target the upstream", got.host)
	}
}

func TestProxyReturnsJSONBadGateway(t *testing.T) {
	handler, err := New([]router.Route{{
		ID: "offline", PathPrefix: "/api/test", Upstream: "http://127.0.0.1:0", Timeout: time.Second,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handlerWithRequestID := middleware.RequestID(handler)

	response := httptest.NewRecorder()
	handlerWithRequestID.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/test/failure", nil))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != "BAD_GATEWAY" {
		t.Errorf("error code = %q, want BAD_GATEWAY", body.Error.Code)
	}
	if body.Error.RequestID == "" {
		t.Error("error request ID is empty")
	}
}

func TestProxyRoutesPrefixesToDifferentUpstreams(t *testing.T) {
	users := httptest.NewServer(upstreamNameHandler("users"))
	defer users.Close()
	orders := httptest.NewServer(upstreamNameHandler("orders"))
	defer orders.Close()

	handler, err := New([]router.Route{
		{ID: "users", PathPrefix: "/api/users", Upstream: users.URL, Timeout: time.Second},
		{ID: "orders", PathPrefix: "/api/orders", Upstream: orders.URL, Timeout: time.Second},
	}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handlerWithRequestID := middleware.RequestID(handler)

	for _, tt := range []struct {
		path string
		want string
	}{
		{path: "/api/users/42", want: "users:/api/users/42"},
		{path: "/api/orders/99", want: "orders:/api/orders/99"},
	} {
		response := httptest.NewRecorder()
		handlerWithRequestID.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", tt.path, response.Code)
		}
		if got := response.Body.String(); got != tt.want {
			t.Fatalf("%s body = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestProxyPreservesPathWithUpstreamBasePath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, err := New([]router.Route{{
		ID: "base", PathPrefix: "/api", Upstream: upstream.URL + "/internal", Timeout: time.Second,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	middleware.RequestID(handler).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/users", nil),
	)
	if gotPath != "/internal/api/users" {
		t.Fatalf("upstream path = %q, want /internal/api/users", gotPath)
	}
}

func TestProxyReturnsJSONNotFound(t *testing.T) {
	handler, err := New([]router.Route{{
		ID: "users", PathPrefix: "/api/users", Upstream: "http://users.example", Timeout: time.Second,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/missing", nil))
	assertJSONError(t, response, http.StatusNotFound, "ROUTE_NOT_FOUND")
}

func TestProxyReturnsJSONGatewayTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()

	handler, err := New([]router.Route{{
		ID: "slow", PathPrefix: "/api/slow", Upstream: upstream.URL, Timeout: 50 * time.Millisecond,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/slow", nil))
	assertJSONError(t, response, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT")
}

func TestProxyDoesNotWriteGatewayErrorAfterClientCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, err := New([]router.Route{{
		ID: "cancel", PathPrefix: "/api/cancel", Upstream: upstream.URL, Timeout: time.Second,
	}}, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/cancel", nil).WithContext(ctx)
	response := &trackingResponseWriter{header: make(http.Header)}
	middleware.RequestID(handler).ServeHTTP(response, request)

	if response.wroteResponse {
		t.Fatal("gateway wrote a response after the client context was cancelled")
	}
}

func upstreamNameHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, name+":"+r.URL.Path)
	})
}

func assertJSONError(t *testing.T, response *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("status = %d, want %d", response.Code, wantStatus)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != wantCode {
		t.Fatalf("error code = %q, want %q", body.Error.Code, wantCode)
	}
	if body.Error.RequestID == "" {
		t.Fatal("error request ID is empty")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type trackingResponseWriter struct {
	header        http.Header
	wroteResponse bool
}

func (w *trackingResponseWriter) Header() http.Header {
	return w.header
}

func (w *trackingResponseWriter) Write(body []byte) (int, error) {
	w.wroteResponse = true
	return len(body), nil
}

func (w *trackingResponseWriter) WriteHeader(_ int) {
	w.wroteResponse = true
}
