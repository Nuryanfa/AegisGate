package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

const proxyTestCredential = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef"

func TestProxyAllowsPublicRouteWithoutCredentialAndForwardsRequest(t *testing.T) {
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

	handler, err := New([]router.Route{
		publicRoute(t, "test", "/api/test", upstream.URL, time.Second),
	}, emptyRegistry(t), discardLogger())
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
	handler, err := New([]router.Route{
		publicRoute(t, "offline", "/api/test", "http://127.0.0.1:0", time.Second),
	}, emptyRegistry(t), discardLogger())
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
		publicRoute(t, "users", "/api/users", users.URL, time.Second),
		publicRoute(t, "orders", "/api/orders", orders.URL, time.Second),
	}, emptyRegistry(t), discardLogger())
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

	handler, err := New([]router.Route{
		publicRoute(t, "base", "/api", upstream.URL+"/internal", time.Second),
	}, emptyRegistry(t), discardLogger())
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
	handler, err := New([]router.Route{
		publicRoute(t, "users", "/api/users", "http://users.example", time.Second),
	}, emptyRegistry(t), discardLogger())
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

	handler, err := New([]router.Route{
		publicRoute(t, "slow", "/api/slow", upstream.URL, 50*time.Millisecond),
	}, emptyRegistry(t), discardLogger())
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

	handler, err := New([]router.Route{
		publicRoute(t, "cancel", "/api/cancel", upstream.URL, time.Second),
	}, emptyRegistry(t), discardLogger())
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

func TestProxyAuthorizesProtectedRouteAndStripsCredentialHeaders(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if got := r.Header.Values(auth.HeaderName); len(got) != 0 {
			t.Errorf("upstream received API key header: %v", got)
		}
		if got := r.Header.Get("X-Aegis-Client-ID"); got != "" {
			t.Errorf("upstream received spoofed identity header %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	registry := registryForCredential(t, proxyTestCredential, []string{"orders:read"})
	handler, err := New([]router.Route{{
		ID:         "orders",
		PathPrefix: "/api/orders",
		Upstream:   upstream.URL,
		Timeout:    time.Second,
		Auth:       protectedPolicy(t, "orders:read"),
	}}, registry, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/orders/42", nil)
	request.Header.Set(auth.HeaderName, proxyTestCredential)
	request.Header.Set("X-Aegis-Client-ID", "spoofed-client")
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
}

func TestProxyRejectsInvalidCredentialsBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	registry := registryForCredential(t, proxyTestCredential, []string{"orders:read"})
	handler, err := New([]router.Route{{
		ID:         "orders",
		PathPrefix: "/api/orders",
		Upstream:   upstream.URL,
		Timeout:    time.Second,
		Auth:       protectedPolicy(t, "orders:read"),
	}}, registry, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		requestURL string
		values     []string
	}{
		{name: "missing", requestURL: "/api/orders"},
		{name: "query string is not accepted", requestURL: "/api/orders?api_key=" + proxyTestCredential},
		{name: "invalid", values: []string{"abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"}},
		{name: "duplicate", values: []string{proxyTestCredential, proxyTestCredential}},
		{name: "empty", values: []string{""}},
		{name: "oversized", values: []string{strings.Repeat("a", auth.MaxCredentialLength+1)}},
		{name: "malformed", values: []string{strings.Repeat("a", 42) + "+"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestURL := tt.requestURL
			if requestURL == "" {
				requestURL = "/api/orders"
			}
			request := httptest.NewRequest(http.MethodGet, requestURL, nil)
			for _, value := range tt.values {
				request.Header.Add(auth.HeaderName, value)
			}
			response := httptest.NewRecorder()
			middleware.RequestID(handler).ServeHTTP(response, request)
			assertJSONError(t, response, http.StatusUnauthorized, "UNAUTHORIZED")
		})
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("rejected requests reached upstream %d times", upstreamCalls.Load())
	}
}

func TestProxyRejectsValidKeyWithInsufficientScope(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	registry := registryForCredential(t, proxyTestCredential, []string{"profile:read"})
	handler, err := New([]router.Route{{
		ID:         "orders",
		PathPrefix: "/api/orders",
		Upstream:   upstream.URL,
		Timeout:    time.Second,
		Auth:       protectedPolicy(t, "orders:read"),
	}}, registry, discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	request.Header.Set(auth.HeaderName, proxyTestCredential)
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, request)

	assertJSONError(t, response, http.StatusForbidden, "FORBIDDEN")
	if upstreamCalls.Load() != 0 {
		t.Fatalf("forbidden request reached upstream %d times", upstreamCalls.Load())
	}
}

func TestProtectedChildCannotBypassThroughPublicParentRoute(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, err := New([]router.Route{
		publicRoute(t, "public-api", "/api", upstream.URL, time.Second),
		{
			ID:         "protected-admin",
			PathPrefix: "/api/admin",
			Upstream:   upstream.URL,
			Timeout:    time.Second,
			Auth:       protectedPolicy(t, "admin:read"),
		},
	}, registryForCredential(t, proxyTestCredential, []string{"admin:read"}), discardLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	protectedResponse := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(
		protectedResponse,
		httptest.NewRequest(http.MethodGet, "/api/admin/secrets", nil),
	)
	assertJSONError(t, protectedResponse, http.StatusUnauthorized, "UNAUTHORIZED")
	if upstreamCalls.Load() != 0 {
		t.Fatalf("protected child bypassed authorization and reached upstream")
	}

	for _, ambiguousPath := range []string{"/api//admin/secrets", "/api/users/../admin/secrets"} {
		response := httptest.NewRecorder()
		middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, ambiguousPath, nil))
		assertJSONError(t, response, http.StatusNotFound, "ROUTE_NOT_FOUND")
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("ambiguous protected path bypassed authorization and reached upstream")
	}

	publicResponse := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(
		publicResponse,
		httptest.NewRequest(http.MethodGet, "/api/profile", nil),
	)
	if publicResponse.Code != http.StatusNoContent {
		t.Fatalf("public parent status = %d, want %d", publicResponse.Code, http.StatusNoContent)
	}
}

func TestRateLimitUsesValidatedClientIdentityAndRejectsBeforeUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	limiter := &stubRateLimiter{decision: ratelimit.Decision{Allowed: false, RetryAfter: 1250 * time.Millisecond}}
	policy := rateLimitPolicy(t, 1, 1, "deny")
	handler, err := NewWithRateLimiter([]router.Route{{
		ID: "orders", PathPrefix: "/api/orders", Upstream: upstream.URL, Timeout: time.Second,
		Auth: protectedPolicy(t, "orders:read"), RateLimit: &policy,
	}}, registryForCredential(t, proxyTestCredential, []string{"orders:read"}), limiter, discardLogger())
	if err != nil {
		t.Fatalf("NewWithRateLimiter() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	request.Header.Set(auth.HeaderName, proxyTestCredential)
	request.Header.Set("X-Aegis-Client-ID", "spoofed")
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, request)

	assertJSONError(t, response, http.StatusTooManyRequests, "RATE_LIMITED")
	if got := response.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
	if limiter.subject != "client:test-client" {
		t.Fatalf("limiter subject = %q, want authenticated client identity", limiter.subject)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("rate-limited request reached upstream")
	}
}

func TestPublicRateLimitUsesDirectPeerAndIgnoresForwardingHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	limiter := &stubRateLimiter{decision: ratelimit.Decision{Allowed: true}}
	policy := rateLimitPolicy(t, 2, 1, "deny")
	route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
	route.RateLimit = &policy
	handler, err := NewWithRateLimiter([]router.Route{route}, emptyRegistry(t), limiter, discardLogger())
	if err != nil {
		t.Fatalf("NewWithRateLimiter() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	request.RemoteAddr = "203.0.113.9:54321"
	request.Header.Set("X-Forwarded-For", "198.51.100.50")
	request.Header.Set("X-Real-IP", "198.51.100.51")
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if limiter.subject != "peer:203.0.113.9" {
		t.Fatalf("limiter subject = %q, want direct peer", limiter.subject)
	}
}

func TestAuthenticationFailureIsNotChargedToRateLimiter(t *testing.T) {
	policy := rateLimitPolicy(t, 1, 1, "deny")
	limiter := &stubRateLimiter{decision: ratelimit.Decision{Allowed: true}}
	handler, err := NewWithRateLimiter([]router.Route{{
		ID: "orders", PathPrefix: "/api/orders", Upstream: "http://orders.example", Timeout: time.Second,
		Auth: protectedPolicy(t, "orders:read"), RateLimit: &policy,
	}}, registryForCredential(t, proxyTestCredential, []string{"orders:read"}), limiter, discardLogger())
	if err != nil {
		t.Fatalf("NewWithRateLimiter() error = %v", err)
	}
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/orders", nil))
	assertJSONError(t, response, http.StatusUnauthorized, "UNAUTHORIZED")
	if limiter.calls.Load() != 0 {
		t.Fatal("invalid credential attempt was charged to authenticated-client limiter")
	}
}

func TestRateLimiterRedisFailureModes(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mode       string
		wantStatus int
		wantCalls  int32
	}{
		{name: "deny", mode: "deny", wantStatus: http.StatusServiceUnavailable, wantCalls: 0},
		{name: "allow", mode: "allow", wantStatus: http.StatusNoContent, wantCalls: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			policy := rateLimitPolicy(t, 1, 1, tt.mode)
			route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
			route.RateLimit = &policy
			handler, err := NewWithRateLimiter([]router.Route{route}, emptyRegistry(t), &stubRateLimiter{err: errors.New("Redis unavailable")}, discardLogger())
			if err != nil {
				t.Fatalf("NewWithRateLimiter() error = %v", err)
			}
			response := httptest.NewRecorder()
			middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/users", nil))
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusServiceUnavailable {
				assertJSONError(t, response, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE")
			}
			if upstreamCalls.Load() != tt.wantCalls {
				t.Fatalf("upstream calls = %d, want %d", upstreamCalls.Load(), tt.wantCalls)
			}
		})
	}
}

func TestWAFAuditAndEnforcePipeline(t *testing.T) {
	tests := []struct {
		mode         string
		wantStatus   int
		wantUpstream int32
		wantAction   string
	}{
		{"audit", http.StatusAccepted, 1, "audit"},
		{"enforce", http.StatusForbidden, 0, "block"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer upstream.Close()
			route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
			policy := proxyWAFPolicy(t, tt.mode, 5, false)
			route.WAF = &policy
			publisher := &stubSecurityEventPublisher{accept: true}
			handler, err := NewWithSecurityEvents([]router.Route{route}, emptyRegistry(t), nil, waf.NewEngine(), publisher, discardLogger())
			if err != nil {
				t.Fatalf("NewWithSecurityEvents() error = %v", err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/users?q=1%27+OR+1%3D1--", strings.NewReader("body-secret-must-not-appear"))
			request.RemoteAddr = "203.0.113.77:4321"
			request.Header.Set(auth.HeaderName, "secret-must-not-appear")
			request.Header.Set("Authorization", "authorization-secret-must-not-appear")
			request.Header.Set("Cookie", "cookie-secret-must-not-appear")
			request.Header.Set("X-Aegis-Client-ID", "client-secret-must-not-appear")
			response := httptest.NewRecorder()
			middleware.RequestID(handler).ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if upstreamCalls.Load() != tt.wantUpstream {
				t.Fatalf("upstream calls = %d, want %d", upstreamCalls.Load(), tt.wantUpstream)
			}
			events := publisher.Events()
			if len(events) != 1 {
				t.Fatalf("published events = %d, want 1", len(events))
			}
			event := events[0]
			if event.SchemaVersion() != securityevent.EventSchemaV1 || event.RouteID() != "users" ||
				len(event.MatchedRuleIDs()) != 1 || event.MatchedRuleIDs()[0] != "AG-1001" || event.Action() != tt.wantAction {
				t.Fatalf("unexpected security event: schema=%q route=%q rules=%v action=%q",
					event.SchemaVersion(), event.RouteID(), event.MatchedRuleIDs(), event.Action())
			}
			allowedValues := strings.Join(append([]string{
				event.RequestID(), event.RouteID(), event.WAFMode(), event.Action(), event.ReasonClass(),
				event.HighestSeverity(), event.Method(), event.PathClassification(),
			}, event.MatchedRuleIDs()...), " ")
			for _, forbidden := range []string{"secret-must-not-appear", "OR 1=1", "203.0.113.77"} {
				if strings.Contains(allowedValues, forbidden) {
					t.Fatalf("security event leaked request data %q: %q", forbidden, allowedValues)
				}
			}
			if tt.mode == "enforce" {
				assertJSONError(t, response, http.StatusForbidden, "WAF_BLOCKED")
			}
		})
	}
}

func TestSlowSecuritySinkDoesNotDelayHTTPDecisions(t *testing.T) {
	for _, tt := range []struct {
		mode         string
		wantStatus   int
		wantUpstream int32
	}{
		{mode: "audit", wantStatus: http.StatusAccepted, wantUpstream: 2},
		{mode: "enforce", wantStatus: http.StatusForbidden, wantUpstream: 1},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer upstream.Close()

			sink := newBlockingSecuritySink()
			options := securityevent.DefaultOptions()
			options.QueueCapacity = 1
			options.DeliveryCapacity = 1
			options.Workers = 1
			options.SinkTimeout = 2 * time.Second
			options.ShutdownTimeout = 2 * time.Second
			options.SummaryInterval = time.Hour
			options.Detection = securityevent.DetectionOptions{}
			pipeline, err := securityevent.NewPipeline(options, sink, discardLogger(), nil)
			if err != nil {
				t.Fatalf("NewPipeline() error = %v", err)
			}
			defer func() {
				sink.Release()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := pipeline.Shutdown(ctx); err != nil {
					t.Errorf("Shutdown() error = %v", err)
				}
			}()

			if !pipeline.Publish(proxyTestSecurityEvent()) {
				t.Fatal("initial security event was not accepted")
			}
			select {
			case <-sink.started:
			case <-time.After(time.Second):
				t.Fatal("sink did not begin processing")
			}
			for i := 0; i < 100 && pipeline.Snapshot().DroppedIngressTotal == 0; i++ {
				pipeline.Publish(proxyTestSecurityEvent())
			}
			if pipeline.Snapshot().DroppedIngressTotal == 0 {
				t.Fatal("failed to saturate bounded pipeline")
			}

			route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
			policy := proxyWAFPolicy(t, tt.mode, 5, false)
			route.WAF = &policy
			handler, err := NewWithSecurityEvents([]router.Route{route}, emptyRegistry(t), nil, waf.NewEngine(), pipeline, discardLogger())
			if err != nil {
				t.Fatalf("NewWithSecurityEvents() error = %v", err)
			}
			requestHandler := middleware.RequestID(handler)

			benign := serveWithin(t, requestHandler, httptest.NewRequest(http.MethodGet, "/api/users?q=hello", nil), 500*time.Millisecond)
			if benign.Code != http.StatusAccepted {
				t.Fatalf("benign status = %d, want %d", benign.Code, http.StatusAccepted)
			}

			blockedOrAudited := serveWithin(t, requestHandler, httptest.NewRequest(http.MethodGet, "/api/users?q=1%27+OR+1%3D1--", nil), 500*time.Millisecond)
			if blockedOrAudited.Code != tt.wantStatus {
				t.Fatalf("WAF status = %d, want %d", blockedOrAudited.Code, tt.wantStatus)
			}
			if upstreamCalls.Load() != tt.wantUpstream {
				t.Fatalf("upstream calls = %d, want %d", upstreamCalls.Load(), tt.wantUpstream)
			}
		})
	}
}

func TestSecurityEventPublisherRequiredForWAF(t *testing.T) {
	route := publicRoute(t, "users", "/api/users", "http://upstream.example", time.Second)
	policy := proxyWAFPolicy(t, "audit", 5, false)
	route.WAF = &policy
	if _, err := NewWithSecurityEvents([]router.Route{route}, emptyRegistry(t), nil, waf.NewEngine(), nil, discardLogger()); err == nil {
		t.Fatal("NewWithSecurityEvents() accepted a WAF route without a publisher")
	}
}

func TestWAFBodyIsRestoredBeforeProxyingAndOversizeNeverReachesUpstream(t *testing.T) {
	var gotBody []byte
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
	policy := proxyWAFPolicy(t, "audit", 5, true)
	route.WAF = &policy
	handler, err := NewWithPolicies([]router.Route{route}, emptyRegistry(t), nil, waf.NewEngine(), discardLogger())
	if err != nil {
		t.Fatalf("NewWithPolicies() error = %v", err)
	}
	body := []byte(`{"name":"O'Connor","comparison":"a < b"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !bytes.Equal(gotBody, body) {
		t.Fatalf("status/body = %d/%q, want exact %q", response.Code, gotBody, body)
	}

	oversize := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(strings.Repeat("x", 257)))
	oversize.Header.Set("Content-Type", "text/plain")
	response = httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, oversize)
	assertJSONError(t, response, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE")
	if upstreamCalls.Load() != 1 {
		t.Fatalf("oversize request reached upstream; calls = %d", upstreamCalls.Load())
	}
}

func TestWAFBelowThresholdAndHardInputErrors(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := publicRoute(t, "users", "/api/users", upstream.URL, time.Second)
	policy := proxyWAFPolicy(t, "enforce", 5, true)
	route.WAF = &policy
	handler, err := NewWithPolicies([]router.Route{route}, emptyRegistry(t), nil, waf.NewEngine(), discardLogger())
	if err != nil {
		t.Fatalf("NewWithPolicies() error = %v", err)
	}

	below := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	below.Header.Set("X-HTTP-Method-Override", "TRACE")
	response := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(response, below)
	if response.Code != http.StatusNoContent {
		t.Fatalf("below-threshold status = %d", response.Code)
	}

	for _, tt := range []struct {
		name, contentType, body, wantCode string
		wantStatus                        int
	}{
		{"malformed JSON", "application/json", "{", "INVALID_REQUEST", http.StatusBadRequest},
		{"unsupported media", "application/octet-stream", "opaque", "UNSUPPORTED_MEDIA_TYPE", http.StatusUnsupportedMediaType},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.contentType)
			response := httptest.NewRecorder()
			middleware.RequestID(handler).ServeHTTP(response, request)
			assertJSONError(t, response, tt.wantStatus, tt.wantCode)
		})
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("hard input error reached upstream; calls = %d", upstreamCalls.Load())
	}
}

func TestAuthenticationAndRateLimitPrecedeWAF(t *testing.T) {
	policy := rateLimitPolicy(t, 1, 1, "deny")
	wafPolicy := proxyWAFPolicy(t, "enforce", 5, true)
	inspector := &stubInspector{}
	limiter := &stubRateLimiter{decision: ratelimit.Decision{Allowed: false, RetryAfter: time.Second}}
	route := publicRoute(t, "orders", "/api/orders", "http://upstream.invalid", time.Second)
	route.Auth = protectedPolicy(t, "orders:read")
	route.RateLimit = &policy
	route.WAF = &wafPolicy
	handler, err := NewWithPolicies([]router.Route{route}, registryForCredential(t, proxyTestCredential, []string{"orders:read"}), limiter, inspector, discardLogger())
	if err != nil {
		t.Fatalf("NewWithPolicies() error = %v", err)
	}

	unauthorized := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/orders", strings.NewReader(strings.Repeat("x", 1000))))
	assertJSONError(t, unauthorized, http.StatusUnauthorized, "UNAUTHORIZED")
	if limiter.calls.Load() != 0 || inspector.calls.Load() != 0 {
		t.Fatal("authentication rejection invoked a later policy")
	}

	limitedRequest := httptest.NewRequest(http.MethodPost, "/api/orders", strings.NewReader(strings.Repeat("x", 1000)))
	limitedRequest.Header.Set(auth.HeaderName, proxyTestCredential)
	limited := httptest.NewRecorder()
	middleware.RequestID(handler).ServeHTTP(limited, limitedRequest)
	assertJSONError(t, limited, http.StatusTooManyRequests, "RATE_LIMITED")
	if inspector.calls.Load() != 0 {
		t.Fatal("rate-limited request incurred WAF inspection")
	}
}

func TestWAFInternalFailurePolicy(t *testing.T) {
	for _, tt := range []struct {
		mode string
		want int
	}{{"audit", http.StatusBadGateway}, {"enforce", http.StatusServiceUnavailable}} {
		t.Run(tt.mode, func(t *testing.T) {
			route := publicRoute(t, "test", "/api", "http://127.0.0.1:0", time.Second)
			policy := proxyWAFPolicy(t, tt.mode, 5, false)
			route.WAF = &policy
			handler, err := NewWithPolicies([]router.Route{route}, emptyRegistry(t), nil, &stubInspector{err: waf.ErrInternal}, discardLogger())
			if err != nil {
				t.Fatalf("NewWithPolicies() error = %v", err)
			}
			response := httptest.NewRecorder()
			middleware.RequestID(handler).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api", nil))
			if response.Code != tt.want {
				t.Fatalf("status = %d, want %d", response.Code, tt.want)
			}
			if tt.mode == "enforce" {
				assertJSONError(t, response, http.StatusServiceUnavailable, "WAF_UNAVAILABLE")
			}
		})
	}
}

func upstreamNameHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, name+":"+r.URL.Path)
	})
}

func serveWithin(t *testing.T, handler http.Handler, request *http.Request, timeout time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-done:
		return response
	case <-time.After(timeout):
		t.Fatalf("HTTP handler did not complete within %s", timeout)
		return nil
	}
}

func proxyTestSecurityEvent() securityevent.Event {
	return securityevent.NewEvent(securityevent.EventInput{
		OccurredAt: time.Now(), RouteID: "users", WAFMode: "audit", Action: "audit",
		ReasonClass: "rule_match", MatchedRuleIDs: []string{"AG-1001"}, Method: http.MethodGet,
		PathClassification: "configured_route",
	})
}

func publicRoute(t *testing.T, id, pathPrefix, upstream string, timeout time.Duration) router.Route {
	t.Helper()
	policy, err := auth.NewPolicy("public", nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return router.Route{
		ID:         id,
		PathPrefix: pathPrefix,
		Upstream:   upstream,
		Timeout:    timeout,
		Auth:       policy,
	}
}

func protectedPolicy(t *testing.T, scopes ...string) auth.Policy {
	t.Helper()
	policy, err := auth.NewPolicy("api_key", scopes)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func emptyRegistry(t *testing.T) *auth.Registry {
	t.Helper()
	registry, err := auth.NewRegistry(nil)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}

func registryForCredential(t *testing.T, plaintext string, scopes []string) *auth.Registry {
	t.Helper()
	digest := sha256.Sum256([]byte(plaintext))
	key, err := auth.NewKey("test-client", fmt.Sprintf("%x", digest), scopes)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	registry, err := auth.NewRegistry([]auth.Key{key})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}

func rateLimitPolicy(t *testing.T, capacity int64, refill float64, mode string) ratelimit.Policy {
	t.Helper()
	policy, err := ratelimit.NewPolicy(capacity, refill, mode)
	if err != nil {
		t.Fatalf("ratelimit.NewPolicy() error = %v", err)
	}
	return policy
}

type stubRateLimiter struct {
	decision ratelimit.Decision
	err      error
	calls    atomic.Int32
	routeID  string
	subject  string
}

type stubInspector struct {
	result waf.Result
	err    error
	calls  atomic.Int32
}

type stubSecurityEventPublisher struct {
	mu     sync.Mutex
	events []securityevent.Event
	accept bool
}

type blockingSecuritySink struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingSecuritySink() *blockingSecuritySink {
	return &blockingSecuritySink{started: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingSecuritySink) Write(ctx context.Context, _ securityevent.Record) error {
	s.startedOnce.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *blockingSecuritySink) Release() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (p *stubSecurityEventPublisher) Publish(event securityevent.Event) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
	return p.accept
}

func (p *stubSecurityEventPublisher) Events() []securityevent.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]securityevent.Event(nil), p.events...)
}

func (i *stubInspector) Inspect(_ *http.Request, _ waf.Policy) (waf.Result, error) {
	i.calls.Add(1)
	return i.result, i.err
}

func proxyWAFPolicy(t *testing.T, mode string, threshold int, body bool) waf.Policy {
	t.Helper()
	inspection := waf.Inspection{Query: true, Headers: true, MaxQueryBytes: 8192, MaxHeaderBytes: 16384}
	if body {
		inspection.Body = true
		inspection.MaxBodyBytes = 256
		inspection.MaxJSONDepth = 10
		inspection.MaxJSONElements = 100
	}
	policy, err := waf.NewPolicy(mode, waf.RuleSetCoreV1, threshold, inspection)
	if err != nil {
		t.Fatalf("waf.NewPolicy() error = %v", err)
	}
	return policy
}

func (l *stubRateLimiter) Allow(_ context.Context, routeID, subject string, _ ratelimit.Policy) (ratelimit.Decision, error) {
	l.calls.Add(1)
	l.routeID = routeID
	l.subject = subject
	return l.decision, l.err
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
