package ratelimit

import (
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	MaxCapacity        = int64(1_000_000)
	MinRefillPerSecond = 0.001
	MaxRefillPerSecond = float64(1_000_000)
	maxTimeToFull      = 12 * time.Hour
)

type FailureMode string

const (
	FailureDeny  FailureMode = "deny"
	FailureAllow FailureMode = "allow"
)

// Policy is an immutable token-bucket policy created through NewPolicy.
type Policy struct {
	capacity        int64
	refillPerSecond float64
	failureMode     FailureMode
	ttl             time.Duration
}

func NewPolicy(capacity int64, refillPerSecond float64, rawFailureMode string) (Policy, error) {
	if capacity <= 0 || capacity > MaxCapacity {
		return Policy{}, fmt.Errorf("capacity must be between 1 and %d", MaxCapacity)
	}
	if math.IsNaN(refillPerSecond) || math.IsInf(refillPerSecond, 0) ||
		refillPerSecond < MinRefillPerSecond || refillPerSecond > MaxRefillPerSecond {
		return Policy{}, fmt.Errorf("refill_per_second must be between %g and %g", MinRefillPerSecond, MaxRefillPerSecond)
	}
	failureMode := FailureMode(rawFailureMode)
	if failureMode != FailureDeny && failureMode != FailureAllow {
		if rawFailureMode == "" {
			return Policy{}, errors.New("on_redis_error is required")
		}
		return Policy{}, fmt.Errorf("unsupported on_redis_error mode %q", rawFailureMode)
	}

	timeToFull := time.Duration(math.Ceil(float64(capacity) / refillPerSecond * float64(time.Second)))
	if timeToFull > maxTimeToFull {
		return Policy{}, fmt.Errorf("capacity/refill_per_second must refill a full bucket within %s", maxTimeToFull)
	}
	ttl := 2 * timeToFull
	if ttl < time.Second {
		ttl = time.Second
	}

	return Policy{
		capacity:        capacity,
		refillPerSecond: refillPerSecond,
		failureMode:     failureMode,
		ttl:             ttl,
	}, nil
}

func (p Policy) Validate() error {
	_, err := NewPolicy(p.capacity, p.refillPerSecond, string(p.failureMode))
	return err
}

func (p Policy) Capacity() int64          { return p.capacity }
func (p Policy) RefillPerSecond() float64 { return p.refillPerSecond }
func (p Policy) FailureMode() FailureMode { return p.failureMode }
func (p Policy) FailClosed() bool         { return p.failureMode == FailureDeny }
func (p Policy) StateTTL() time.Duration  { return p.ttl }

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}
