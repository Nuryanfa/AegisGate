package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/prometheus/client_golang/prometheus"
)

type fixedSnapshot struct{ value securityevent.Snapshot }

func (s fixedSnapshot) Snapshot() securityevent.Snapshot { return s.value }

func metricValue(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, sample := range family.Metric {
			matching := true
			for key, value := range labels {
				found := false
				for _, pair := range sample.Label {
					if pair.GetName() == key && pair.GetValue() == value {
						found = true
					}
				}
				if !found {
					matching = false
				}
			}
			if matching {
				if sample.Counter != nil {
					return sample.Counter.GetValue()
				}
				if sample.Gauge != nil {
					return sample.Gauge.GetValue()
				}
				if sample.Histogram != nil {
					return float64(sample.Histogram.GetSampleCount())
				}
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return 0
}

func TestMetricsRequestAndPolicyOutcomes(t *testing.T) {
	m := NewMetrics("test", "commit", "build", nil)
	m.BeginRequest()
	if got := metricValue(t, m, "aegisgate_http_requests_in_flight", nil); got != 1 {
		t.Fatal(got)
	}
	m.EndRequest("users", "GET", OutcomeUnauthorized, http.StatusUnauthorized, 3*time.Millisecond)
	if got := metricValue(t, m, "aegisgate_http_requests_in_flight", nil); got != 0 {
		t.Fatal(got)
	}
	if got := metricValue(t, m, "aegisgate_http_requests_total", map[string]string{"route_id": "users", "status_class": "4xx", "outcome": "unauthorized"}); got != 1 {
		t.Fatal(got)
	}
	if got := metricValue(t, m, "aegisgate_http_request_duration_seconds", map[string]string{"outcome": "unauthorized"}); got != 1 {
		t.Fatal(got)
	}
	m.ObserveAuth("users", "forbidden")
	m.ObserveRate("users", "deny", time.Millisecond)
	m.ObserveWAF("users", "enforce", "block", time.Millisecond)
	m.ObserveUpstream("users", "timeout", time.Second)
	for _, name := range []string{"aegisgate_auth_decisions_total", "aegisgate_rate_limit_decisions_total", "aegisgate_waf_decisions_total", "aegisgate_upstream_requests_total"} {
		if got := metricValue(t, m, name, map[string]string{"route_id": "users"}); got != 1 {
			t.Fatalf("%s=%v", name, got)
		}
	}
	response := httptest.NewRecorder()
	m.Handler("/metrics").ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), "aegisgate_build_info") {
		t.Fatal(response.Code)
	}
	for _, secret := range []string{"/api/users/secret", "client-id", "api-key"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("leaked %q", secret)
		}
	}
	notFound := httptest.NewRecorder()
	m.Handler("/metrics").ServeHTTP(notFound, httptest.NewRequest("GET", "/other", nil))
	if notFound.Code != 404 {
		t.Fatal(notFound.Code)
	}
}

func TestPrivateRegistriesAndSnapshotCollector(t *testing.T) {
	snapshot := securityevent.Snapshot{AcceptedTotal: 4, DroppedIngressTotal: 2, ProcessedTotal: 3, AlertsGeneratedTotal: 1, DeliveredTotal: 2, DroppedDeliveryTotal: 1, SinkErrorsTotal: 1, IngressQueueDepth: 7, DeliveryQueueDepth: 8, ActiveDetectionKeys: 9}
	a, b := NewMetrics("dev", "unknown", "unknown", fixedSnapshot{snapshot}), NewMetrics("dev", "unknown", "unknown", nil)
	if got := metricValue(t, a, "aegisgate_security_events_total", nil); got != 4 {
		t.Fatal(got)
	}
	if got := metricValue(t, a, "aegisgate_security_event_ingress_queue_depth", nil); got != 7 {
		t.Fatal(got)
	}
	if got := metricValue(t, a, "aegisgate_security_event_active_detection_keys", nil); got != 9 {
		t.Fatal(got)
	}
	a.BeginRequest()
	a.EndRequest("users", "GET", OutcomeSuccess, 200, 0)
	if got := metricValue(t, b, "aegisgate_http_requests_in_flight", nil); got != 0 {
		t.Fatal(got)
	}
	for _, collector := range []prometheus.Collector{newPipelineCollector(fixedSnapshot{snapshot})} {
		if err := a.Registry().Register(collector); err == nil {
			t.Fatal("duplicate collector accepted")
		}
	}
}
