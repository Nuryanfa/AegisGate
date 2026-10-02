package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nuryanfa/AegisGate/internal/observability"
)

func TestStatusWriterOptionalCapabilities(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &statusWriter{ResponseWriter: recorder, status: 200}
	if _, ok := any(writer).(http.Flusher); !ok {
		t.Fatal("flush capability missing")
	}
	writer.Flush()
	if !recorder.Flushed || writer.status != 200 {
		t.Fatal("flush did not reach underlying writer")
	}
	if _, err := writer.ReadFrom(strings.NewReader("stream")); err != nil {
		t.Fatal(err)
	}
	if recorder.Body.String() != "stream" {
		t.Fatal(recorder.Body.String())
	}
	if err := writer.Push("/resource", nil); err != http.ErrNotSupported {
		t.Fatalf("push = %v", err)
	}
	if _, _, err := writer.Hijack(); err == nil {
		t.Fatal("unsupported hijack unexpectedly succeeded")
	}
}

func TestRequestCompletionCorrelationAndCancellation(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	metrics := observability.NewMetrics("test", "unknown", "unknown", nil)
	handler := observability.Middleware(nil, metrics, LoggingWithObservability(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observability.SetRequestRoute(r.Context(), "users", "/api/users")
		_, _ = io.WriteString(w, "ok")
	}), metrics))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/users/42", nil))
	if strings.Count(logs.String(), "request completed") != 1 {
		t.Fatal(logs.String())
	}

	logs.Reset()
	cancelled := observability.Middleware(nil, metrics, LoggingWithObservability(logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), metrics))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/users", nil).WithContext(ctx))
	if !strings.Contains(logs.String(), `"status":0`) {
		t.Fatal(logs.String())
	}
}
