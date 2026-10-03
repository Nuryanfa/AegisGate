package observability

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ControlPlaneMetrics has fixed label vocabularies and no runtime identifiers.
type ControlPlaneMetrics struct {
	Connected     prometheus.Gauge
	Reconnects    prometheus.Counter
	Received      prometheus.Counter
	Apply         *prometheus.CounterVec
	ApplyDuration prometheus.Histogram
	LastSuccess   prometheus.Gauge
	Stale         prometheus.Gauge
	Clients       prometheus.Gauge
	Published     prometheus.Counter
	ACKs          prometheus.Counter
	NACKs         prometheus.Counter
	Reload        *prometheus.CounterVec
}

func NewControlPlaneMetrics(registry *prometheus.Registry) *ControlPlaneMetrics {
	m := &ControlPlaneMetrics{
		Connected:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "aegisgate_control_plane_connected", Help: "Gateway control-plane connection state."}),
		Reconnects:    prometheus.NewCounter(prometheus.CounterOpts{Name: "aegisgate_control_plane_reconnects_total", Help: "Gateway reconnect attempts."}),
		Received:      prometheus.NewCounter(prometheus.CounterOpts{Name: "aegisgate_control_plane_snapshots_received_total", Help: "Received configuration snapshots."}),
		Apply:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_control_plane_snapshot_apply_total", Help: "Snapshot application outcomes."}, []string{"result", "reason"}),
		ApplyDuration: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "aegisgate_control_plane_snapshot_apply_duration_seconds", Help: "Snapshot validation and application duration.", Buckets: latencyBuckets}),
		LastSuccess:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "aegisgate_control_plane_last_success_timestamp_seconds", Help: "Unix time of last accepted snapshot."}),
		Stale:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "aegisgate_control_plane_stale", Help: "Whether configuration is stale."}),
		Clients:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "aegisgate_control_plane_clients", Help: "Connected gateway streams."}),
		Published:     prometheus.NewCounter(prometheus.CounterOpts{Name: "aegisgate_control_plane_snapshots_published_total", Help: "Changed snapshots published."}),
		ACKs:          prometheus.NewCounter(prometheus.CounterOpts{Name: "aegisgate_control_plane_acks_total", Help: "Gateway acknowledgements."}),
		NACKs:         prometheus.NewCounter(prometheus.CounterOpts{Name: "aegisgate_control_plane_nacks_total", Help: "Gateway rejections."}),
		Reload:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "aegisgate_control_plane_reload_total", Help: "Snapshot reload outcomes."}, []string{"result"}),
	}
	registry.MustRegister(m.Connected, m.Reconnects, m.Received, m.Apply, m.ApplyDuration, m.LastSuccess, m.Stale, m.Clients, m.Published, m.ACKs, m.NACKs, m.Reload)
	return m
}

func (m *ControlPlaneMetrics) ObserveApply(result, reason string, duration time.Duration) {
	if m == nil {
		return
	}
	switch result {
	case "success", "unchanged", "rejected", "failed":
	default:
		result = "failed"
	}
	switch reason {
	case "none", "validation", "dependency", "stale", "protocol", "capacity":
	default:
		reason = "validation"
	}
	m.Apply.WithLabelValues(result, reason).Inc()
	m.ApplyDuration.Observe(duration.Seconds())
}

func (m *ControlPlaneMetrics) ObserveReload(result string) {
	if m == nil {
		return
	}
	switch result {
	case "success", "unchanged", "rejected":
	default:
		result = "rejected"
	}
	m.Reload.WithLabelValues(result).Inc()
}
