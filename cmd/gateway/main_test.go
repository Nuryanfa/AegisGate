package main

import (
	"testing"

	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/waf"
)

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
