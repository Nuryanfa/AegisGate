package ratelimit

import (
	"strings"
	"testing"
	"time"
)

func TestPolicyValidationAndDerivedTTL(t *testing.T) {
	policy, err := NewPolicy(20, 5, "deny")
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if policy.Capacity() != 20 || policy.RefillPerSecond() != 5 || !policy.FailClosed() {
		t.Fatalf("unexpected policy: %#v", policy)
	}
	if policy.StateTTL() != 8*time.Second {
		t.Fatalf("StateTTL() = %s, want 8s", policy.StateTTL())
	}

	tests := []struct {
		name     string
		capacity int64
		refill   float64
		mode     string
	}{
		{name: "zero capacity", refill: 1, mode: "deny"},
		{name: "excessive capacity", capacity: MaxCapacity + 1, refill: 1, mode: "deny"},
		{name: "zero refill", capacity: 1, mode: "deny"},
		{name: "excessive refill", capacity: 1, refill: MaxRefillPerSecond + 1, mode: "deny"},
		{name: "missing failure mode", capacity: 1, refill: 1},
		{name: "unknown failure mode", capacity: 1, refill: 1, mode: "sometimes"},
		{name: "unbounded retention", capacity: MaxCapacity, refill: MinRefillPerSecond, mode: "deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewPolicy(tt.capacity, tt.refill, tt.mode); err == nil {
				t.Fatal("NewPolicy() accepted invalid policy")
			}
		})
	}
}

func TestBucketKeyHasFixedNamespaceAndHidesInputs(t *testing.T) {
	key := bucketKey("orders", "client:customer-visible-id")
	if !strings.HasPrefix(key, bucketNamespace+":") {
		t.Fatalf("bucket key %q has wrong namespace", key)
	}
	if strings.Contains(key, "orders") || strings.Contains(key, "customer-visible-id") {
		t.Fatalf("bucket key exposes route or subject: %q", key)
	}
	if len(key) != len(bucketNamespace)+1+64+1+64 {
		t.Fatalf("bucket key length = %d, want fixed digest length", len(key))
	}
}
