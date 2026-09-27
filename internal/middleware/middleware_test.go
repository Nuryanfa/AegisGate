package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDPreservesExistingID(t *testing.T) {
	const existing = "client-request-id"
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestIDFromContext(r.Context()); got != existing {
			t.Errorf("context request ID = %q, want %q", got, existing)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(RequestIDHeader, existing)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if got := response.Header().Get(RequestIDHeader); got != existing {
		t.Fatalf("response request ID = %q, want %q", got, existing)
	}
}

func TestRequestIDGeneratesMissingID(t *testing.T) {
	var contextID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	headerID := response.Header().Get(RequestIDHeader)
	if headerID == "" {
		t.Fatal("response request ID is empty")
	}
	if headerID != contextID {
		t.Fatalf("response request ID = %q, context ID = %q", headerID, contextID)
	}
}

func TestLoggingCapturesCompletedResponse(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	handler := RequestID(Logging(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/items", nil))

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if got := int(entry["status"].(float64)); got != http.StatusCreated {
		t.Fatalf("logged status = %d, want %d", got, http.StatusCreated)
	}
	if got := entry["path"]; got != "/items" {
		t.Fatalf("logged path = %v, want /items", got)
	}
	if got := entry["request_id"]; got == "" {
		t.Fatal("logged request ID is empty")
	}
}
