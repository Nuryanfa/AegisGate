package observability

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	OutcomeSuccess               = "success"
	OutcomeRouteNotFound         = "route_not_found"
	OutcomeInvalidRequest        = "invalid_request"
	OutcomeUnauthorized          = "unauthorized"
	OutcomeForbidden             = "forbidden"
	OutcomeRateLimited           = "rate_limited"
	OutcomeDependencyUnavailable = "dependency_unavailable"
	OutcomeWAFBlocked            = "waf_blocked"
	OutcomeUpstreamTimeout       = "upstream_timeout"
	OutcomeUpstreamError         = "upstream_error"
	OutcomeInternalError         = "internal_error"
	OutcomeClientCancelled       = "client_cancelled"
)

var latencyBuckets = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

type SnapshotSource interface{ Snapshot() securityevent.Snapshot }

type Metrics struct {
	routeMu          sync.Mutex
	admittedRoutes   map[string]struct{}
	registry         *prometheus.Registry
	requests         *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	inFlight         prometheus.Gauge
	upstream         *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
	auth             *prometheus.CounterVec
	rate             *prometheus.CounterVec
	rateDuration     *prometheus.HistogramVec
	waf              *prometheus.CounterVec
	wafDuration      *prometheus.HistogramVec
}

func NewMetrics(version, commit, buildTime string, pipeline SnapshotSource) *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{registry: r, admittedRoutes: make(map[string]struct{}),
		requests:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_http_requests_total", Help: "Completed gateway HTTP requests."}, []string{"route_id", "method", "status_class", "outcome"}),
		requestDuration:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "aegisgate_http_request_duration_seconds", Help: "Gateway request duration through response completion.", Buckets: latencyBuckets}, []string{"route_id", "method", "outcome"}),
		inFlight:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "aegisgate_http_requests_in_flight", Help: "Active gateway HTTP requests."}),
		upstream:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_upstream_requests_total", Help: "Upstream transport outcomes."}, []string{"route_id", "result"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "aegisgate_upstream_request_duration_seconds", Help: "Upstream time to response headers or transport error.", Buckets: latencyBuckets}, []string{"route_id", "result"}),
		auth:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_auth_decisions_total", Help: "Gateway authentication and authorization decisions."}, []string{"route_id", "decision"}),
		rate:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_rate_limit_decisions_total", Help: "Rate-limit policy decisions."}, []string{"route_id", "decision"}),
		rateDuration:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "aegisgate_rate_limit_check_duration_seconds", Help: "Redis rate-limit check duration.", Buckets: latencyBuckets}, []string{"route_id"}),
		waf:              prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_waf_decisions_total", Help: "WAF inspection decisions."}, []string{"route_id", "mode", "action"}),
		wafDuration:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "aegisgate_waf_inspection_duration_seconds", Help: "Synchronous WAF inspection duration.", Buckets: latencyBuckets}, []string{"route_id"}),
	}
	r.MustRegister(m.requests, m.requestDuration, m.inFlight, m.upstream, m.upstreamDuration, m.auth, m.rate, m.rateDuration, m.waf, m.wafDuration)
	r.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "aegisgate_build_info", Help: "Static build metadata; value is one.", ConstLabels: prometheus.Labels{"version": version, "commit": commit, "build_time": buildTime}}, func() float64 { return 1 }))
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if pipeline != nil {
		r.MustRegister(newPipelineCollector(pipeline))
	}
	return m
}

func (m *Metrics) Registry() *prometheus.Registry { return m.registry }
func (m *Metrics) Handler(path string) http.Handler {
	h := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
func (m *Metrics) BeginRequest() {
	if m != nil {
		m.inFlight.Inc()
	}
}
func (m *Metrics) EndRequest(route, method, outcome string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	m.inFlight.Dec()
	route = m.routeLabel(route)
	method = metricMethod(method)
	outcome = metricOutcome(outcome)
	m.requests.WithLabelValues(route, method, statusClass(status), outcome).Inc()
	m.requestDuration.WithLabelValues(route, method, outcome).Observe(duration.Seconds())
}
func (m *Metrics) ObserveUpstream(route, result string, duration time.Duration) {
	if m == nil {
		return
	}
	if result != "success" && result != "timeout" {
		result = "error"
	}
	route = m.routeLabel(route)
	m.upstream.WithLabelValues(route, result).Inc()
	m.upstreamDuration.WithLabelValues(route, result).Observe(duration.Seconds())
}
func (m *Metrics) ObserveAuth(route, decision string) {
	if m == nil {
		return
	}
	switch decision {
	case "public", "allow", "unauthorized", "forbidden":
	default:
		decision = "unauthorized"
	}
	m.auth.WithLabelValues(m.routeLabel(route), decision).Inc()
}
func (m *Metrics) ObserveRate(route, decision string, duration time.Duration) {
	if m == nil {
		return
	}
	switch decision {
	case "allow", "deny", "dependency_allow", "dependency_deny":
	default:
		decision = "dependency_deny"
	}
	route = m.routeLabel(route)
	m.rate.WithLabelValues(route, decision).Inc()
	m.rateDuration.WithLabelValues(route).Observe(duration.Seconds())
}
func (m *Metrics) ObserveWAF(route, mode, action string, duration time.Duration) {
	if m == nil {
		return
	}
	if mode != "audit" && mode != "enforce" {
		mode = "disabled"
	}
	switch action {
	case "allow", "audit", "block", "reject", "fail_open", "fail_closed":
	default:
		action = "reject"
	}
	route = m.routeLabel(route)
	m.waf.WithLabelValues(route, mode, action).Inc()
	m.wafDuration.WithLabelValues(route).Observe(duration.Seconds())
}
func metricRoute(route string) string {
	if route == "" {
		return "_none"
	}
	return route
}

// A process admits at most 64 distinct route IDs across all reloads. Additional
// routes share _other, so repeated configuration churn cannot grow series forever.
func (m *Metrics) routeLabel(route string) string {
	if route == "" {
		return "_none"
	}
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	if _, ok := m.admittedRoutes[route]; ok {
		return route
	}
	if len(m.admittedRoutes) >= 64 {
		return "_other"
	}
	m.admittedRoutes[route] = struct{}{}
	return route
}
func metricMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return method
	}
	return "OTHER"
}
func metricOutcome(outcome string) string {
	switch outcome {
	case OutcomeSuccess, OutcomeRouteNotFound, OutcomeInvalidRequest, OutcomeUnauthorized, OutcomeForbidden, OutcomeRateLimited, OutcomeDependencyUnavailable, OutcomeWAFBlocked, OutcomeUpstreamTimeout, OutcomeUpstreamError, OutcomeInternalError, OutcomeClientCancelled:
		return outcome
	}
	return OutcomeInternalError
}
func statusClass(status int) string {
	if status < 100 || status >= 600 {
		return "other"
	}
	return strconv.Itoa(status/100) + "xx"
}

type snapshotMetric struct {
	desc   *prometheus.Desc
	typeOf prometheus.ValueType
	value  func(securityevent.Snapshot) float64
}
type pipelineCollector struct {
	source  SnapshotSource
	metrics []snapshotMetric
}

func newPipelineCollector(source SnapshotSource) *pipelineCollector {
	makeMetric := func(name, help string, kind prometheus.ValueType, value func(securityevent.Snapshot) float64) snapshotMetric {
		return snapshotMetric{prometheus.NewDesc(name, help, nil, nil), kind, value}
	}
	return &pipelineCollector{source: source, metrics: []snapshotMetric{
		makeMetric("aegisgate_security_events_total", "Accepted security events.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.AcceptedTotal) }),
		makeMetric("aegisgate_security_event_ingress_drops_total", "Dropped newest ingress events.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.DroppedIngressTotal) }),
		makeMetric("aegisgate_security_event_processed_total", "Events processed by the detector.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.ProcessedTotal) }),
		makeMetric("aegisgate_security_event_alerts_total", "Generated process-local alerts.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.AlertsGeneratedTotal) }),
		makeMetric("aegisgate_security_event_delivery_total", "Successfully delivered records.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.DeliveredTotal) }),
		makeMetric("aegisgate_security_event_delivery_drops_total", "Abandoned delivery records.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.DroppedDeliveryTotal) }),
		makeMetric("aegisgate_security_event_sink_errors_total", "Failed sink writes.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.SinkErrorsTotal) }),
		makeMetric("aegisgate_security_event_detection_key_drops_total", "New detector keys rejected at capacity.", prometheus.CounterValue, func(s securityevent.Snapshot) float64 { return float64(s.DetectionKeysDroppedTotal) }),
		makeMetric("aegisgate_security_event_ingress_queue_depth", "Current ingress queue depth.", prometheus.GaugeValue, func(s securityevent.Snapshot) float64 { return float64(s.IngressQueueDepth) }),
		makeMetric("aegisgate_security_event_delivery_queue_depth", "Current delivery queue depth.", prometheus.GaugeValue, func(s securityevent.Snapshot) float64 { return float64(s.DeliveryQueueDepth) }),
		makeMetric("aegisgate_security_event_active_detection_keys", "Current process-local detector keys.", prometheus.GaugeValue, func(s securityevent.Snapshot) float64 { return float64(s.ActiveDetectionKeys) }),
	}}
}
func (c *pipelineCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m.desc
	}
}
func (c *pipelineCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.source.Snapshot()
	for _, m := range c.metrics {
		ch <- prometheus.MustNewConstMetric(m.desc, m.typeOf, m.value(snapshot))
	}
}
