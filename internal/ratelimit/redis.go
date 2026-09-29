package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	redis "github.com/redis/go-redis/v9"
)

const bucketNamespace = "aegisgate:rl:v1"

var tokenBucketScript = redis.NewScript(`
local capacity = tonumber(ARGV[1])
local refill_per_second = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])

local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state = redis.call('HMGET', KEYS[1], 'tokens', 'last_ms')
local tokens = tonumber(state[1])
local last_ms = tonumber(state[2])

if tokens == nil or last_ms == nil then
  tokens = capacity
  last_ms = now_ms
else
  local elapsed_ms = now_ms - last_ms
  if elapsed_ms < 0 then
    elapsed_ms = 0
    now_ms = last_ms
  end
  tokens = math.min(capacity, tokens + elapsed_ms * refill_per_second / 1000)
end

local allowed = 0
local retry_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_ms = math.max(1, math.ceil((1 - tokens) * 1000 / refill_per_second))
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'last_ms', now_ms)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return {allowed, retry_ms}
`)

type RedisOptions struct {
	Address        string
	Username       string
	Password       string
	Database       int
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	PoolSize       int
}

type RedisLimiter struct {
	client *redis.Client
}

func NewRedisLimiter(options RedisOptions) (*RedisLimiter, error) {
	if options.Address == "" {
		return nil, errors.New("Redis address must not be empty")
	}
	if options.ConnectTimeout <= 0 || options.CommandTimeout <= 0 || options.PoolSize <= 0 {
		return nil, errors.New("Redis connection timeout, command timeout, and pool size must be positive")
	}
	client := redis.NewClient(&redis.Options{
		Addr:           options.Address,
		Username:       options.Username,
		Password:       options.Password,
		DB:             options.Database,
		DialTimeout:    options.ConnectTimeout,
		ReadTimeout:    options.CommandTimeout,
		WriteTimeout:   options.CommandTimeout,
		PoolTimeout:    options.ConnectTimeout,
		PoolSize:       options.PoolSize,
		MaxActiveConns: options.PoolSize,
		MaxRetries:     -1,
	})
	return &RedisLimiter{client: client}, nil
}

func (l *RedisLimiter) Allow(ctx context.Context, routeID, subject string, policy Policy) (Decision, error) {
	if err := policy.Validate(); err != nil {
		return Decision{}, fmt.Errorf("invalid rate-limit policy: %w", err)
	}
	if routeID == "" || subject == "" {
		return Decision{}, errors.New("rate-limit route and subject must not be empty")
	}

	result, err := tokenBucketScript.Run(ctx, l.client, []string{bucketKey(routeID, subject)},
		policy.Capacity(),
		strconv.FormatFloat(policy.RefillPerSecond(), 'g', -1, 64),
		policy.StateTTL().Milliseconds(),
	).Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("execute Redis rate-limit decision: %w", err)
	}
	if len(result) != 2 {
		return Decision{}, errors.New("Redis rate-limit script returned an invalid result")
	}
	allowed, err := redisResultInt64(result[0])
	if err != nil {
		return Decision{}, err
	}
	retryMilliseconds, err := redisResultInt64(result[1])
	if err != nil {
		return Decision{}, err
	}
	return Decision{
		Allowed:    allowed == 1,
		RetryAfter: time.Duration(retryMilliseconds) * time.Millisecond,
	}, nil
}

func (l *RedisLimiter) Ping(ctx context.Context) error {
	if err := l.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis readiness check failed: %w", err)
	}
	return nil
}

func (l *RedisLimiter) Close() error {
	return l.client.Close()
}

func bucketKey(routeID, subject string) string {
	routeDigest := sha256.Sum256([]byte(routeID))
	subjectDigest := sha256.Sum256([]byte(subject))
	return bucketNamespace + ":" + hex.EncodeToString(routeDigest[:]) + ":" + hex.EncodeToString(subjectDigest[:])
}

func redisResultInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, errors.New("Redis rate-limit script returned a non-integer result")
		}
		return parsed, nil
	default:
		return 0, errors.New("Redis rate-limit script returned an unexpected result type")
	}
}
