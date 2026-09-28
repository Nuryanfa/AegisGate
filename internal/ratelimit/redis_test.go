package ratelimit

import (
	"testing"
	"time"
)

func TestRedisLimiterOptionsAreBoundedAndExplicit(t *testing.T) {
	if _, err := NewRedisLimiter(RedisOptions{}); err == nil {
		t.Fatal("NewRedisLimiter() accepted empty options")
	}
	if _, err := NewRedisLimiter(RedisOptions{
		Address: "127.0.0.1:6379", ConnectTimeout: time.Second, CommandTimeout: time.Second,
	}); err == nil {
		t.Fatal("NewRedisLimiter() accepted an unbounded zero-size pool")
	}
	limiter, err := NewRedisLimiter(RedisOptions{
		Address: "127.0.0.1:6379", ConnectTimeout: time.Second, CommandTimeout: time.Second, PoolSize: 1,
	})
	if err != nil {
		t.Fatalf("NewRedisLimiter() error = %v", err)
	}
	// go-redis normalizes configured MaxRetries -1 to zero internally, which
	// means the retry loop is disabled.
	if limiter.client.Options().PoolSize != 1 || limiter.client.Options().MaxActiveConns != 1 || limiter.client.Options().MaxRetries != 0 {
		t.Fatalf("Redis pool/retry bounds were not applied: %#v", limiter.client.Options())
	}
	if err := limiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
