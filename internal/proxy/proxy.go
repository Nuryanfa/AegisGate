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
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/Nuryanfa/AegisGate/internal/waf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Handler matches requests and forwards them to the configured upstream.
type Handler struct {
	router    *router.Router
	proxies   map[string]http.Handler
	auth      *auth.Registry
	limiter   RateLimiter
	inspector RequestInspector
	events    SecurityEventPublisher
	metrics   *observability.Metrics
	tracing   *observability.Tracing
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
	return newHandler(routes, registry, limiter, inspector, nil, nil, nil, logger)
}

// NewWithSecurityEvents builds the production policy pipeline and requires an
// asynchronous publisher whenever at least one route enables WAF inspection.
func NewWithSecurityEvents(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, publisher SecurityEventPublisher, logger *slog.Logger) (*Handler, error) {
	for _, route := range routes {
		if route.WAF != nil && route.WAF.Enabled() && publisher == nil {
			return nil, fmt.Errorf("route %q enables WAF inspection but no security-event publisher is configured", route.ID)
		}
	}
	return newHandler(routes, registry, limiter, inspector, publisher, nil, nil, logger)
}

func NewWithObservability(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, publisher SecurityEventPublisher, metrics *observability.Metrics, tracing *observability.Tracing, logger *slog.Logger) (*Handler, error) {
	for _, route := range routes {
		if route.WAF != nil && route.WAF.Enabled() && publisher == nil {
			return nil, fmt.Errorf("route %q enables WAF inspection but no security-event publisher is configured", route.ID)
		}
	}
	return newHandler(routes, registry, limiter, inspector, publisher, metrics, tracing, logger)
}

func newHandler(routes []router.Route, registry *auth.Registry, limiter RateLimiter, inspector RequestInspector, publisher SecurityEventPublisher, metrics *observability.Metrics, tracing *observability.Tracing, logger *slog.Logger) (*Handler, error) {
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
		proxies[route.ID] = reverseProxy(upstream, route.ID, metrics, tracing, logger)
	}

	return &Handler{router: routeTable, proxies: proxies, auth: registry, limiter: limiter, inspector: inspector, events: publisher, metrics: metrics, tracing: tracing, logger: logger}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := h.router.Match(r.URL.Path)
	if !ok {
		observability.SetRequestOutcome(r.Context(), observability.OutcomeRouteNotFound)
		writeError(w, http.StatusNotFound, "ROUTE_NOT_FOUND", "no route configured for request", middleware.RequestIDFromContext(r.Context()))
		return
	}
	observability.SetRequestRoute(r.Context(), route.ID, route.PathPrefix)
	identity, err := h.auth.Authorize(route.Auth, r.Header)
	if err != nil {
		requestID := middleware.RequestIDFromContext(r.Context())
		if errors.Is(err, auth.ErrForbidden) {
			h.metrics.ObserveAuth(route.ID, "forbidden")
			observability.SetDecision(r.Context(), "aegisgate.auth.outcome", "forbidden")
			observability.SetRequestOutcome(r.Context(), observability.OutcomeForbidden)
			writeError(w, http.StatusForbidden, "FORBIDDEN", "API key lacks required scope", requestID)
			return
		}
		h.metrics.ObserveAuth(route.ID, "unauthorized")
		observability.SetDecision(r.Context(), "aegisgate.auth.outcome", "unauthorized")
		observability.SetRequestOutcome(r.Context(), observability.OutcomeUnauthorized)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "valid API key required", requestID)
		return
	}
	authDecision := "public"
	if route.Auth.RequiresAPIKey() {
		authDecision = "allow"
	}
	h.metrics.ObserveAuth(route.ID, authDecision)
	observability.SetDecision(r.Context(), "aegisgate.auth.outcome", authDecision)
	if route.RateLimit != nil {
		subject, err := rateLimitSubject(route, identity, r.RemoteAddr)
		if err != nil {
			h.metrics.ObserveRate(route.ID, "dependency_deny", 0)
			observability.SetRequestOutcome(r.Context(), observability.OutcomeDependencyUnavailable)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "rate-limit service unavailable", middleware.RequestIDFromContext(r.Context()))
			return
		}
		checkCtx := r.Context()
		var checkSpan trace.Span
		if h.tracing != nil && h.tracing.Enabled() {
			checkCtx, checkSpan = h.tracing.StartCheck(checkCtx, "rate_limit.check")
		}
		started := time.Now()
		decision, err := h.limiter.Allow(checkCtx, route.ID, subject, *route.RateLimit)
		checkDuration := time.Since(started)
		if checkSpan != nil {
			if err != nil {
				checkSpan.SetStatus(codes.Error, "dependency_unavailable")
			}
			checkSpan.End()
		}
		if err != nil {
			if route.RateLimit.FailureMode() == ratelimit.FailureAllow {
				h.metrics.ObserveRate(route.ID, "dependency_allow", checkDuration)
				observability.SetDecision(r.Context(), "aegisgate.rate_limit.outcome", "dependency_allow")
				h.logger.WarnContext(r.Context(), "rate limiter unavailable; request allowed by policy",
					"request_id", middleware.RequestIDFromContext(r.Context()),
					"route_id", route.ID,
					"error", err,
				)
			} else {
				h.metrics.ObserveRate(route.ID, "dependency_deny", checkDuration)
				observability.SetDecision(r.Context(), "aegisgate.rate_limit.outcome", "dependency_deny")
				observability.SetRequestOutcome(r.Context(), observability.OutcomeDependencyUnavailable)
				writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "rate-limit service unavailable", middleware.RequestIDFromContext(r.Context()))
				return
			}
		} else if !decision.Allowed {
			h.metrics.ObserveRate(route.ID, "deny", checkDuration)
			observability.SetDecision(r.Context(), "aegisgate.rate_limit.outcome", "deny")
			observability.SetRequestOutcome(r.Context(), observability.OutcomeRateLimited)
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(decision.RetryAfter), 10))
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded", middleware.RequestIDFromContext(r.Context()))
			return
		} else {
			h.metrics.ObserveRate(route.ID, "allow", checkDuration)
			observability.SetDecision(r.Context(), "aegisgate.rate_limit.outcome", "allow")
		}
	}
	if route.WAF != nil && route.WAF.Enabled() {
		inspectRequest := r
		var inspectSpan trace.Span
		if h.tracing != nil && h.tracing.Enabled() {
			var spanCtx context.Context
			spanCtx, inspectSpan = h.tracing.StartCheck(r.Context(), "waf.inspect")
			inspectRequest = r.WithContext(spanCtx)
		}
		result, err := h.inspector.Inspect(inspectRequest, *route.WAF)
		if inspectSpan != nil {
			if err != nil {
				var clientError *waf.ClientError
				if !errors.As(err, &clientError) {
					inspectSpan.SetStatus(codes.Error, "internal_failure")
				}
			}
			inspectSpan.End()
		}
		observability.SetDecision(r.Context(), "aegisgate.waf.mode", string(route.WAF.Mode()))
		if err != nil {
			var clientError *waf.ClientError
			action := "allow"
			if errors.As(err, &clientError) || route.WAF.Enforces() {
				action = "reject"
			}
			metricAction := "fail_open"
			if clientError != nil {
				metricAction = "reject"
			} else if route.WAF.Enforces() {
				metricAction = "fail_closed"
			}
			h.metrics.ObserveWAF(route.ID, string(route.WAF.Mode()), metricAction, result.Duration)
			observability.SetDecision(r.Context(), "aegisgate.waf.action", metricAction)
			h.publishWAFEvent(r, route, result, action, wafErrorKind(err))
			if errors.As(err, &clientError) {
				observability.SetRequestOutcome(r.Context(), observability.OutcomeInvalidRequest)
				writeError(w, clientError.Status, clientError.Code, clientError.Message, middleware.RequestIDFromContext(r.Context()))
				return
			}
			if route.WAF.Enforces() {
				observability.SetRequestOutcome(r.Context(), observability.OutcomeDependencyUnavailable)
				writeError(w, http.StatusServiceUnavailable, "WAF_UNAVAILABLE", "request inspection service unavailable", middleware.RequestIDFromContext(r.Context()))
				return
			}
		} else {
			h.metrics.ObserveWAF(route.ID, string(route.WAF.Mode()), string(result.Action), result.Duration)
			observability.SetDecision(r.Context(), "aegisgate.waf.action", string(result.Action))
			if len(result.MatchedRuleIDs) > 0 {
				h.publishWAFEvent(r, route, result, string(result.Action), "rule_match")
			}
		}
		if err == nil && result.Action == waf.ActionBlock {
			observability.SetRequestOutcome(r.Context(), observability.OutcomeWAFBlocked)
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

func reverseProxy(upstream *url.URL, routeID string, metrics *observability.Metrics, tracing *observability.Tracing, logger *slog.Logger) *httputil.ReverseProxy {
	var transport http.RoundTripper
	if metrics != nil || (tracing != nil && tracing.Enabled()) {
		transport = &observedTransport{base: http.DefaultTransport, routeID: routeID, host: upstream.Hostname(), metrics: metrics, tracing: tracing}
	}
	return &httputil.ReverseProxy{
		Transport: transport,
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
			// Never pass client-supplied trace headers through unchanged. The
			// observed transport injects the current context only when enabled.
			request.Out.Header.Del("traceparent")
			request.Out.Header.Del("tracestate")
			request.Out.Header.Del("baggage")
			request.SetXForwarded()
			request.Out.Header.Set(middleware.RequestIDHeader, middleware.RequestIDFromContext(request.In.Context()))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			requestID := middleware.RequestIDFromContext(r.Context())
			if errors.Is(context.Cause(r.Context()), errRouteTimeout) {
				observability.SetRequestOutcome(r.Context(), observability.OutcomeUpstreamTimeout)
				writeTimeout(logger, upstream, w, r, requestID)
				return
			}
			if r.Context().Err() != nil {
				observability.SetRequestOutcome(r.Context(), observability.OutcomeClientCancelled)
				logger.InfoContext(r.Context(), "upstream request cancelled by client",
					"request_id", requestID,
					"upstream", upstream.Redacted(),
				)
				return
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				observability.SetRequestOutcome(r.Context(), observability.OutcomeUpstreamTimeout)
				writeTimeout(logger, upstream, w, r, requestID)
				return
			}
			logger.ErrorContext(r.Context(), "upstream request failed",
				"request_id", requestID,
				"upstream", upstream.Redacted(),
				"error", err,
			)
			observability.SetRequestOutcome(r.Context(), observability.OutcomeUpstreamError)
			writeError(w, http.StatusBadGateway, "BAD_GATEWAY", "upstream service unavailable", requestID)
		},
		ModifyResponse: func(response *http.Response) error {
			if response.StatusCode >= 500 {
				observability.SetRequestOutcome(response.Request.Context(), observability.OutcomeUpstreamError)
			}
			return nil
		},
	}
}

type observedTransport struct {
	base          http.RoundTripper
	routeID, host string
	metrics       *observability.Metrics
	tracing       *observability.Tracing
}

func (t *observedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	started := time.Now()
	if t.tracing != nil && t.tracing.Enabled() {
		ctx, span := t.tracing.StartUpstream(request.Context(), t.routeID, t.host)
		defer span.End()
		request = request.Clone(ctx)
		t.tracing.Inject(ctx, request.Header)
		response, err := t.base.RoundTrip(request)
		result := upstreamResult(request.Context(), response, err)
		t.metrics.ObserveUpstream(t.routeID, result, time.Since(started))
		if result != "success" {
			span.SetStatus(codes.Error, result)
		}
		if response != nil {
			span.SetAttributes(attribute.Int("http.response.status_code", response.StatusCode))
		}
		return response, err
	}
	response, err := t.base.RoundTrip(request)
	t.metrics.ObserveUpstream(t.routeID, upstreamResult(request.Context(), response, err), time.Since(started))
	return response, err
}

func upstreamResult(ctx context.Context, response *http.Response, err error) string {
	if err != nil {
		var netErr net.Error
		if errors.Is(context.Cause(ctx), errRouteTimeout) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			return "timeout"
		}
		return "error"
	}
	if response != nil && response.StatusCode >= 500 {
		return "error"
	}
	return "success"
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
