package observability

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRouteLabelAdmissionIsBounded(t *testing.T) {
	m := NewMetrics("dev", "unknown", "unknown", nil)
	for i := 0; i < 1000; i++ {
		m.ObserveAuth(fmt.Sprintf("route-%d", i), "public")
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "aegisgate_auth_decisions_total" && len(family.Metric) > 65 {
			t.Fatalf("route labels grew to %d", len(family.Metric))
		}
	}
}

func TestControlPlaneMetricsUseFixedLabels(t *testing.T) {
	r := prometheus.NewRegistry()
	m := NewControlPlaneMetrics(r)
	m.ObserveApply("arbitrary", "secret", 0)
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "aegisgate_control_plane_snapshot_apply_total" {
			if len(family.Metric) != 1 {
				t.Fatalf("metrics=%d", len(family.Metric))
			}
			for _, label := range family.Metric[0].Label {
				if label.GetValue() == "secret" {
					t.Fatal("unbounded metric label")
				}
			}
		}
	}
}
