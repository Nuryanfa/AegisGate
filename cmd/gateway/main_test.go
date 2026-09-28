package main

import (
	"testing"

	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
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

func mustGatewayRatePolicy(t *testing.T, mode string) ratelimit.Policy {
	t.Helper()
	policy, err := ratelimit.NewPolicy(1, 1, mode)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}
