package ratelimit

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedisTokenBucketRefillIsolationAndExpiration(t *testing.T) {
	limiter := integrationLimiter(t)
	cleanupBuckets(t, limiter, [][2]string{{"orders", "client:first"}, {"orders", "client:second"}, {"users", "client:first"}, {"expiry", "peer:192.0.2.1"}})
	ctx := context.Background()
	policy := mustRatePolicy(t, 2, 5, "deny")

	for range 2 {
		decision, err := limiter.Allow(ctx, "orders", "client:first", policy)
		if err != nil || !decision.Allowed {
			t.Fatalf("initial bucket decision = %#v, %v; want allowed", decision, err)
		}
	}
	denied, err := limiter.Allow(ctx, "orders", "client:first", policy)
	if err != nil || denied.Allowed || denied.RetryAfter <= 0 || denied.RetryAfter > 250*time.Millisecond {
		t.Fatalf("exhausted bucket decision = %#v, %v", denied, err)
	}

	for _, key := range [][2]string{{"orders", "client:second"}, {"users", "client:first"}} {
		decision, err := limiter.Allow(ctx, key[0], key[1], policy)
		if err != nil || !decision.Allowed {
			t.Fatalf("independent bucket %v decision = %#v, %v", key, decision, err)
		}
	}

	time.Sleep(250 * time.Millisecond)
	refilled, err := limiter.Allow(ctx, "orders", "client:first", policy)
	if err != nil || !refilled.Allowed {
		t.Fatalf("refilled bucket decision = %#v, %v; want allowed", refilled, err)
	}

	expiring := mustRatePolicy(t, 1, 1000, "deny")
	if _, err := limiter.Allow(ctx, "expiry", "peer:192.0.2.1", expiring); err != nil {
		t.Fatalf("create expiring bucket: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for limiter.client.Exists(ctx, bucketKey("expiry", "peer:192.0.2.1")).Val() != 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if exists := limiter.client.Exists(ctx, bucketKey("expiry", "peer:192.0.2.1")).Val(); exists != 0 {
		t.Fatalf("inactive bucket still exists after bounded TTL")
	}
}

func TestRedisTokenBucketIsAtomicAcrossLimiterInstances(t *testing.T) {
	first := integrationLimiter(t)
	cleanupBuckets(t, first, [][2]string{{"shared-route", "client:shared"}})
	second := integrationLimiter(t)
	policy := mustRatePolicy(t, 20, 0.01, "deny")

	const requests = 100
	var allowed atomic.Int32
	errors := make(chan error, requests)
	var group sync.WaitGroup
	group.Add(requests)
	for index := range requests {
		go func() {
			defer group.Done()
			limiter := first
			if index%2 == 1 {
				limiter = second
			}
			decision, err := limiter.Allow(context.Background(), "shared-route", "client:shared", policy)
			if err == nil && decision.Allowed {
				allowed.Add(1)
			}
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Allow() error = %v", err)
		}
	}
	if got := allowed.Load(); got != 20 {
		t.Fatalf("allowed requests = %d, want exactly 20", got)
	}
}

func TestRedisTokenBucketDefendsAgainstFutureTimestamp(t *testing.T) {
	limiter := integrationLimiter(t)
	cleanupBuckets(t, limiter, [][2]string{{"clock", "client:clock"}})
	ctx := context.Background()
	serverTime, err := limiter.client.Time(ctx).Result()
	if err != nil {
		t.Fatalf("Redis TIME: %v", err)
	}
	key := bucketKey("clock", "client:clock")
	futureMilliseconds := serverTime.Add(time.Hour).UnixMilli()
	if err := limiter.client.HSet(ctx, key, "tokens", 0, "last_ms", futureMilliseconds).Err(); err != nil {
		t.Fatalf("seed future timestamp: %v", err)
	}

	decision, err := limiter.Allow(ctx, "clock", "client:clock", mustRatePolicy(t, 1, 1, "deny"))
	if err != nil || decision.Allowed {
		t.Fatalf("future timestamp decision = %#v, %v; want denied without negative refill", decision, err)
	}
	storedTimestamp, err := limiter.client.HGet(ctx, key, "last_ms").Int64()
	if err != nil || storedTimestamp != futureMilliseconds {
		t.Fatalf("stored timestamp = %d, %v; want future timestamp preserved", storedTimestamp, err)
	}
}

func integrationLimiter(t *testing.T) *RedisLimiter {
	t.Helper()
	address := os.Getenv("AEGIS_REDIS_INTEGRATION_ADDR")
	if address == "" {
		t.Skip("AEGIS_REDIS_INTEGRATION_ADDR is not set; real Redis integration test skipped")
	}
	limiter, err := NewRedisLimiter(RedisOptions{
		Address: address, ConnectTimeout: 2 * time.Second, CommandTimeout: 2 * time.Second, PoolSize: 20,
	})
	if err != nil {
		t.Fatalf("NewRedisLimiter() error = %v", err)
	}
	t.Cleanup(func() { _ = limiter.Close() })
	if err := limiter.Ping(context.Background()); err != nil {
		t.Fatalf("Redis unavailable at integration address: %v", err)
	}
	return limiter
}

func cleanupBuckets(t *testing.T, limiter *RedisLimiter, subjects [][2]string) {
	t.Helper()
	keys := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		keys = append(keys, bucketKey(subject[0], subject[1]))
	}
	deleteKeys := func() {
		if err := limiter.client.Del(context.Background(), keys...).Err(); err != nil {
			t.Errorf("delete test-owned Redis keys: %v", err)
		}
	}
	deleteKeys()
	t.Cleanup(deleteKeys)
}

func mustRatePolicy(t *testing.T, capacity int64, refill float64, mode string) Policy {
	t.Helper()
	policy, err := NewPolicy(capacity, refill, mode)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}
