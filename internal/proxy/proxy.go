package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/router"
)

// Handler matches requests and forwards them to the configured upstream.
type Handler struct {
	router  *router.Router
	proxies map[string]http.Handler
}

var errRouteTimeout = errors.New("route timeout exceeded")

// New validates routes and builds one reverse proxy per upstream route.
func New(routes []router.Route, logger *slog.Logger) (*Handler, error) {
	routeTable, err := router.New(routes)
	if err != nil {
		return nil, err
	}

	proxies := make(map[string]http.Handler, len(routes))
	for _, route := range routes {
		upstream, err := url.Parse(route.Upstream)
		if err != nil {
			return nil, fmt.Errorf("parse upstream for route %q: %w", route.ID, err)
		}
		if (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" {
			return nil, fmt.Errorf("route %q upstream must be an absolute HTTP URL", route.ID)
		}
		if upstream.User != nil {
			return nil, fmt.Errorf("route %q upstream must not include credentials", route.ID)
		}
		if upstream.RawQuery != "" || upstream.Fragment != "" {
			return nil, fmt.Errorf("route %q upstream must not include a query or fragment", route.ID)
		}
		proxies[route.ID] = reverseProxy(upstream, logger)
	}

	return &Handler{router: routeTable, proxies: proxies}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := h.router.Match(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "ROUTE_NOT_FOUND", "no route configured for request", middleware.RequestIDFromContext(r.Context()))
		return
	}

	ctx, cancel := context.WithTimeoutCause(r.Context(), route.Timeout, errRouteTimeout)
	defer cancel()
	h.proxies[route.ID].ServeHTTP(w, r.WithContext(ctx))
}

func reverseProxy(upstream *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(upstream)
			request.Out.Host = upstream.Host

			// Rewrite mode removes client-supplied forwarding headers before this
			// callback. Also remove non-standard variants an upstream might trust,
			// then rebuild the standard set from the connection AegisGate observed.
			for name := range request.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
					request.Out.Header.Del(name)
				}
			}
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Real-IP")
			request.SetXForwarded()
			request.Out.Header.Set(middleware.RequestIDHeader, middleware.RequestIDFromContext(request.In.Context()))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			requestID := middleware.RequestIDFromContext(r.Context())
			if errors.Is(context.Cause(r.Context()), errRouteTimeout) {
				writeTimeout(logger, upstream, w, r, requestID)
				return
			}
			if r.Context().Err() != nil {
				logger.InfoContext(r.Context(), "upstream request cancelled by client",
					"request_id", requestID,
					"upstream", upstream.Redacted(),
				)
				return
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				writeTimeout(logger, upstream, w, r, requestID)
				return
			}
			logger.ErrorContext(r.Context(), "upstream request failed",
				"request_id", requestID,
				"upstream", upstream.Redacted(),
				"error", err,
			)
			writeError(w, http.StatusBadGateway, "BAD_GATEWAY", "upstream service unavailable", requestID)
		},
	}
}

func writeTimeout(logger *slog.Logger, upstream *url.URL, w http.ResponseWriter, r *http.Request, requestID string) {
	logger.WarnContext(r.Context(), "upstream request timed out",
		"request_id", requestID,
		"upstream", upstream.Redacted(),
	)
	writeError(w, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "upstream service timed out", requestID)
}

func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	type errorDetail struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	type errorResponse struct {
		Error errorDetail `json:"error"`
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: errorDetail{
		Code: code, Message: message, RequestID: requestID,
	}})
}
