package middleware

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/observability"
)

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// Unwrap allows net/http response controllers to reach optional capabilities
// implemented by the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *statusWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func (w *statusWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(reader)
	}
	return io.Copy(w.ResponseWriter, reader)
}

// Logging records a completed request without inspecting or logging its body.
func Logging(logger *slog.Logger, next http.Handler) http.Handler {
	return LoggingWithObservability(logger, next, nil)
}

func LoggingWithObservability(logger *slog.Logger, next http.Handler, metrics *observability.Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(writer, r)
		state := observability.StateFromContext(r.Context())
		route, outcome := "", observability.OutcomeSuccess
		if state != nil {
			route, outcome = state.RouteID, state.Outcome
		}
		if writer.status >= 500 && outcome == observability.OutcomeSuccess {
			outcome = observability.OutcomeInternalError
		}
		if !writer.wroteHeader && errors.Is(r.Context().Err(), context.Canceled) {
			outcome = observability.OutcomeClientCancelled
			writer.status = 0
		}
		observability.SetOutcome(r.Context(), outcome, writer.status)
		if metrics != nil {
			metrics.EndRequest(route, r.Method, outcome, writer.status, time.Since(started))
		}
		attrs := []any{
			"request_id", RequestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", writer.status,
			"duration_ms", time.Since(started).Milliseconds(),
			"remote_addr", r.RemoteAddr,
		}
		if traceID, spanID := observability.TraceIDs(r.Context()); traceID != "" {
			attrs = append(attrs, "trace_id", traceID, "span_id", spanID)
		}
		logger.InfoContext(r.Context(), "request completed", attrs...)
	})
}
