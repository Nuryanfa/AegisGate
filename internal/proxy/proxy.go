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
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

// Handler matches requests and forwards them to the configured upstream.
type Handler struct {
	router    *router.Router
	proxies   map[string]http.Handler
	auth      *auth.Registry
	limiter   RateLimiter
	inspector RequestInspector
	events    SecurityEventPublisher
	logger    *slog.Logger
}

type RateLimiter interface {
	Allow(context.Context, string, string, ratelimit.Policy) (ratelimit.Decision, error)
}

type RequestInspector interface {
	Inspect(*http.Request, waf.Policy) (waf.Result, error)
}

type SecurityEventPublisher interface {
	Publish(securityevent.Event) bool
}

var errRouteTimeout = errors.New("route timeout exceeded")

// New validates routes and builds one reverse proxy per upstream route.
func New(routes []router.Route, registry *auth.Registry, logger *slog.Logger) (*Handler, error) {
	return NewWithRateLimiter(routes, registry, nil, logger)
}

// NewWithRateLimiter builds a proxy pipeline with optional Redis-backed rate limiting.
func NewWithRateLimiter(routes []router.Route, registry *auth.Registry, limiter RateLimiter, logger *slog.Logger) (*Handler, error) {
	return NewWithPolicies(routes, registry, limiter, nil, logger)
}

// NewWithPolicies builds the complete authentication, rate-limit, inspection,
// and reverse-proxy pipeline without performing a second route match.
func NewWithPolicies(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, logger *slog.Logger) (*Handler, error) {
	return newHandler(routes, registry, limiter, inspector, nil, logger)
}

// NewWithSecurityEvents builds the production policy pipeline and requires an
// asynchronous publisher whenever at least one route enables WAF inspection.
func NewWithSecurityEvents(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, publisher SecurityEventPublisher, logger *slog.Logger) (*Handler, error) {
	for _, route := range routes {
		if route.WAF != nil && route.WAF.Enabled() && publisher == nil {
			return nil, fmt.Errorf("route %q enables WAF inspection but no security-event publisher is configured", route.ID)
		}
	}
	return newHandler(routes, registry, limiter, inspector, publisher, logger)
}

func newHandler(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, publisher SecurityEventPublisher, logger *slog.Logger) (*Handler, error) {
	if registry == nil {
		return nil, errors.New("API key registry must not be nil")
	}
	for _, route := range routes {
		if route.RateLimit != nil && limiter == nil {
			return nil, fmt.Errorf("route %q enables rate limiting but no limiter is configured", route.ID)
		}
		if route.WAF != nil && route.WAF.Enabled() && inspector == nil {
			return nil, fmt.Errorf("route %q enables WAF inspection but no inspector is configured", route.ID)
		}
	}
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

	return &Handler{router: routeTable, proxies: proxies, auth: registry, limiter: limiter, inspector: inspector, events: publisher, logger: logger}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := h.router.Match(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "ROUTE_NOT_FOUND", "no route configured for request", middleware.RequestIDFromContext(r.Context()))
		return
	}
	identity, err := h.auth.Authorize(route.Auth, r.Header)
	if err != nil {
		requestID := middleware.RequestIDFromContext(r.Context())
		if errors.Is(err, auth.ErrForbidden) {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "API key lacks required scope", requestID)
			return
		}
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "valid API key required", requestID)
		return
	}
	if route.RateLimit != nil {
		subject, err := rateLimitSubject(route, identity, r.RemoteAddr)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "rate-limit service unavailable", middleware.RequestIDFromContext(r.Context()))
			return
		}
		decision, err := h.limiter.Allow(r.Context(), route.ID, subject, *route.RateLimit)
		if err != nil {
			if route.RateLimit.FailureMode() == ratelimit.FailureAllow {
				h.logger.WarnContext(r.Context(), "rate limiter unavailable; request allowed by policy",
					"request_id", middleware.RequestIDFromContext(r.Context()),
					"route_id", route.ID,
					"error", err,
				)
			} else {
				writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "rate-limit service unavailable", middleware.RequestIDFromContext(r.Context()))
				return
			}
		} else if !decision.Allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(decision.RetryAfter), 10))
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded", middleware.RequestIDFromContext(r.Context()))
			return
		}
	}
	if route.WAF != nil && route.WAF.Enabled() {
		result, err := h.inspector.Inspect(r, *route.WAF)
		if err != nil {
			var clientError *waf.ClientError
			action := "allow"
			if errors.As(err, &clientError) || route.WAF.Enforces() {
				action = "reject"
			}
			h.publishWAFEvent(r, route, result, action, wafErrorKind(err))
			if errors.As(err, &clientError) {
				writeError(w, clientError.Status, clientError.Code, clientError.Message, middleware.RequestIDFromContext(r.Context()))
				return
			}
			if route.WAF.Enforces() {
				writeError(w, http.StatusServiceUnavailable, "WAF_UNAVAILABLE", "request inspection service unavailable", middleware.RequestIDFromContext(r.Context()))
				return
			}
		} else if len(result.MatchedRuleIDs) > 0 {
			h.publishWAFEvent(r, route, result, string(result.Action), "rule_match")
		}
		if err == nil && result.Action == waf.ActionBlock {
			writeError(w, http.StatusForbidden, "WAF_BLOCKED", "request rejected by security policy", middleware.RequestIDFromContext(r.Context()))
			return
		}
	}

	ctx, cancel := context.WithTimeoutCause(r.Context(), route.Timeout, errRouteTimeout)
	defer cancel()
	h.proxies[route.ID].ServeHTTP(w, r.WithContext(ctx))
}

func (h *Handler) publishWAFEvent(r *http.Request, route router.Route, result waf.Result, action, reason string) {
	if h.events == nil {
		return
	}
	h.events.Publish(securityevent.NewEvent(securityevent.EventInput{
		OccurredAt: time.Now().UTC(), RequestID: middleware.RequestIDFromContext(r.Context()), RouteID: route.ID,
		WAFMode: string(route.WAF.Mode()), Action: action, ReasonClass: reason,
		AnomalyScore: result.AnomalyScore, MatchedRuleIDs: result.MatchedRuleIDs,
		HighestSeverity: string(result.HighestSeverity), Method: r.Method,
		PathClassification: pathClass(route.PathPrefix, r.URL.Path), InspectionDuration: result.Duration,
	}))
}

func pathClass(prefix, requestPath string) string {
	if requestPath == prefix {
		return "route_root"
	}
	return "route_descendant"
}

func wafErrorKind(err error) string {
	var clientError *waf.ClientError
	if errors.As(err, &clientError) {
		return clientError.Kind
	}
	return "internal_failure"
}

func rateLimitSubject(route router.Route, identity auth.Identity, remoteAddr string) (string, error) {
	if route.Auth.RequiresAPIKey() {
		clientID, ok := identity.ClientID()
		if !ok {
			return "", errors.New("authenticated route has no client identity")
		}
		return "client:" + clientID, nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", errors.New("direct peer address is invalid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("direct peer IP is invalid")
	}
	return "peer:" + address.Unmap().String(), nil
}

func retryAfterSeconds(value time.Duration) int64 {
	if value <= 0 {
		return 1
	}
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
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
				lowerName := strings.ToLower(name)
				if strings.HasPrefix(lowerName, "x-forwarded-") ||
					lowerName == strings.ToLower(auth.HeaderName) ||
					strings.HasPrefix(lowerName, "x-aegis-") {
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
