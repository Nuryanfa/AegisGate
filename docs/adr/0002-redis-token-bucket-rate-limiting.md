# ADR 0002: Redis token-bucket rate limiting

Status: Accepted

Date: 2026-09-28

## Context

AegisGate v0.4 needs a quota shared by multiple gateway instances. Local
in-memory counters cannot provide a distributed decision, and separate Redis
reads and writes would admit too many requests under concurrency.

The limiter also needs an explicit identity boundary. Authenticated callers
have a validated API-client ID, while public requests have no trusted client
identity or trusted-proxy model.

## Options considered

1. Per-process token buckets. Fast and dependency-free, but every gateway
   instance would grant a separate quota.
2. Redis `GET` followed by application-side computation and `SET`. This has
   race windows and cannot enforce capacity under concurrent gateways.
3. A Redis Lua token bucket. One server-side script can read, refill, decide,
   consume, and expire state atomically.
4. Fixed-window counters. Simpler, but boundary bursts are less predictable
   than the requested token-bucket behavior.

## Decision

- Each configured route may omit `rate_limit`; omission means no rate limiting.
- A bucket is independent per route and subject. Routes do not share quota.
- Authenticated routes use the client ID returned by successful v0.3 API-key
  authentication. Authentication and scope checks happen before charging.
- Public routes use the direct socket peer IP. Incoming `Forwarded`,
  `X-Forwarded-For`, `X-Real-IP`, and identity-looking headers are not trusted.
- Redis keys use a fixed `aegisgate:rl:v1` namespace and SHA-256 hashes of the
  route ID and typed subject. Raw IDs, IPs, paths, and credentials are absent.
- A Lua script atomically performs read, refill, decision, one-token consume,
  state write, and expiry. Redis `TIME` is the shared clock. Negative elapsed
  time is clamped to zero without moving the stored timestamp backwards, and
  token count never exceeds capacity. Client retries are disabled because a
  lost script response cannot prove whether its token consumption committed.
- Buckets start full. `capacity` is the maximum burst and
  `refill_per_second` is a positive token rate. Decimal rates are supported.
- Inactive state expires after twice the time required to refill an empty
  bucket, with a one-second minimum. Validation bounds time-to-full to 12 hours,
  so state TTL is at most 24 hours.
- `on_redis_error` is mandatory for an enabled policy. `deny` returns JSON 503;
  `allow` continues without enforcement and emits a safe warning. Redis errors
  never masquerade as quota exhaustion.
- Quota exhaustion returns JSON 429 and `Retry-After` as the ceiling of the
  server-calculated time until one token is available, in whole seconds.
- Redis dial and command timeouts plus connection-pool size are bounded. Redis
  credentials are accepted only from `AEGIS_REDIS_USERNAME` and
  `AEGIS_REDIS_PASSWORD`, not YAML.
- `/healthz` remains process liveness. `/readyz` checks Redis when any route is
  fail-closed; configurations containing only fail-open policies remain ready
  during a Redis outage because their declared behavior is to continue.

## Consequences

All AegisGate instances using the same Redis database and namespace share the
same route/subject quota. Redis is in the request path for limited routes, so
its latency and availability directly affect fail-closed traffic. Fail-open
routes trade availability for temporary loss of enforcement.

Public IP-based identity groups users behind the same NAT and can be unstable
when a reverse proxy sits directly in front of AegisGate. A trusted-proxy model
must be designed before using forwarded client addresses.

Invalid API-key attempts are rejected before the authenticated-client bucket
and are not covered by this limiter. A separate coarse direct-peer abuse limit
is intentionally deferred; v0.4 must not claim brute-force or DDoS protection.
Redis persistence is disabled in the local demo because limiter state is
ephemeral by design.
