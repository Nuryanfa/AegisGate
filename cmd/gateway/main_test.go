package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

func TestSuppliedBuildMetadataAppearsInStartupAndMetrics(t *testing.T) {
	oldVersion, oldCommit, oldBuildTime := version, commit, buildTime
	version, commit, buildTime = "v0.7.0-rc1", "abc123def456", "2026-10-02T12:00:00Z"
	t.Cleanup(func() { version, commit, buildTime = oldVersion, oldCommit, oldBuildTime })

	var output bytes.Buffer
	logStartup(slog.New(slog.NewJSONHandler(&output, nil)), config.Config{Environment: "test"}, nil, nil, nil)
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "AegisGate initialized" || entry["version"] != version || entry["commit"] != commit || entry["build_time"] != buildTime {
		t.Fatalf("startup metadata = %v", entry)
	}

	families, err := newBuildMetrics(nil).Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "aegisgate_build_info" {
			continue
		}
		if len(family.Metric) != 1 || family.Metric[0].Gauge.GetValue() != 1 {
			t.Fatal("invalid build info gauge")
		}
		got := make(map[string]string)
		for _, label := range family.Metric[0].Label {
			got[label.GetName()] = label.GetValue()
		}
		if got["version"] != version || got["commit"] != commit || got["build_time"] != buildTime {
			t.Fatalf("build_info labels = %v", got)
		}
		return
	}
	t.Fatal("aegisgate_build_info missing")
}

func TestRateLimitReadinessDependencySelection(t *testing.T) {
	deny := mustGatewayRatePolicy(t, "deny")
	allow := mustGatewayRatePolicy(t, "allow")

	if hasFailClosedRateLimit([]router.Route{{RateLimit: &allow}}) {
		t.Fatal("fail-open-only routes unexpectedly require Redis readiness")
	}
	if !hasFailClosedRateLimit([]router.Route{{RateLimit: &allow}, {RateLimit: &deny}}) {
		t.Fatal("fail-closed route did not require Redis readiness")
	}
	if got := rateLimitedRouteCount([]router.Route{{}, {RateLimit: &allow}, {RateLimit: &deny}}); got != 2 {
		t.Fatalf("rateLimitedRouteCount() = %d, want 2", got)
	}
}

func TestWAFEnabledRouteCount(t *testing.T) {
	disabled, err := waf.NewPolicy("disabled", "", 0, waf.Inspection{})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := waf.NewPolicy("audit", waf.RuleSetCoreV1, 5, waf.Inspection{Query: true, MaxQueryBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if got := wafEnabledRouteCount([]router.Route{{}, {WAF: &disabled}, {WAF: &audit}}); got != 1 {
		t.Fatalf("wafEnabledRouteCount() = %d, want 1", got)
	}
}

func mustGatewayRatePolicy(t *testing.T, mode string) ratelimit.Policy {
	t.Helper()
	policy, err := ratelimit.NewPolicy(1, 1, mode)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}
