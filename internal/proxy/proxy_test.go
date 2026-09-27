package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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

	handler, err := New([]router.Route{{ID: "test", Path: "/api/test/*", Upstream: upstream.URL}}, discardLogger())
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
	handler, err := New([]router.Route{{ID: "offline", Path: "/api/test/*", Upstream: "http://127.0.0.1:0"}}, discardLogger())
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

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
