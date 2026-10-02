# AegisGate

AegisGate is a portfolio-grade API gateway and security platform written in
Go. v0.6 adds a bounded asynchronous security-event pipeline and deterministic
process-local burst detection to the v0.5 WAF gateway.

This is an educational, production-like project, not a claim of production
readiness. An API key identifies a calling application, not a human user.

## Capabilities

- Standard-library HTTP server and reverse proxy
- Strict, startup-only YAML configuration
- Boundary-aware longest-prefix routing and per-route deadlines
- Explicit public or API-key-protected routes
- SHA-256-only key registry with all-required scope authorization
- Atomic Redis token buckets shared across gateway instances
- Explicit per-route fail-open or fail-closed Redis behavior
- Per-route WAF `disabled`, `audit`, and `enforce` modes with anomaly scoring
- Bounded query, header, JSON, form, and plain-text inspection
- Non-blocking, bounded security-event publication with fixed sink workers
- Process-local `AG-D2001` rule-activity and `AG-D2002` block-activity detection
- JSON `400`, `401`, `403`, `404`, `413`, `414`, `415`, `429`, `502`, `503`, and
  `504` errors
- Request IDs, structured logs, forwarding-header sanitization, health checks,
  graceful shutdown, and race-oriented tests
- Non-root image and Compose demo with internal-only Redis

Go 1.25.x is required. Docker Compose is needed only for the container demo.

## Configuration

`AEGIS_CONFIG_PATH` selects one required YAML file. Routes and API-key digests
come only from this file. Server values use this precedence:

```text
environment variable -> YAML server value -> built-in default
```

Supported overrides are `AEGIS_ENV`, `AEGIS_HTTP_ADDR`,
`AEGIS_READ_TIMEOUT`, `AEGIS_WRITE_TIMEOUT`, `AEGIS_IDLE_TIMEOUT`, and
`AEGIS_SHUTDOWN_TIMEOUT`. Redis ACL credentials, when needed, come only from
`AEGIS_REDIS_USERNAME` and `AEGIS_REDIS_PASSWORD`. They are never stored in
committed YAML. Removed v0.1 variable `AEGIS_UPSTREAM_URL` is rejected.

```yaml
server:
  write_timeout: 15s

redis:
  address: localhost:6379
  database: 0
  connect_timeout: 2s
  command_timeout: 500ms
  pool_size: 20

security_events:
  queue_capacity: 1024
  delivery_capacity: 1024
  workers: 2
  sink_timeout: 1s
  shutdown_timeout: 5s
  summary_interval: 30s
  detection:
    enabled: true
    window: 30s
    rule_match_threshold: 10
    block_threshold: 10
    cooldown: 1m
    max_keys: 4096

api_keys:
  - id: orders-client
    sha256: <64-hex-character-sha256-digest>
    scopes: [orders:read]

routes:
  - id: users
    path_prefix: /api/users
    upstream: http://localhost:8081
    timeout: 5s
    auth:
      mode: public
    rate_limit:
      capacity: 20
      refill_per_second: 5
      on_redis_error: deny
    waf:
      mode: audit
      rule_set: core-v1
      anomaly_threshold: 5
      inspection:
        query: true
        headers: true
        body: true
        max_query_bytes: 8192
        max_header_bytes: 16384
        max_body_bytes: 1048576
        max_json_depth: 20
        max_json_elements: 1000

  - id: orders
    path_prefix: /api/orders
    upstream: http://localhost:8082
    timeout: 8s
    auth:
      mode: api_key
      required_scopes: [orders:read]
    rate_limit:
      capacity: 10
      refill_per_second: 2
      on_redis_error: deny
```

Every route must explicitly choose `public` or `api_key`. Public routes cannot
require scopes. Protected routes require exactly one `X-API-Key` header, and
the key must contain every required scope. Query credentials, duplicate header
values, malformed values, and values outside 32–128 base64url-safe characters
are rejected.

Only a SHA-256 digest belongs in configuration. Key IDs, digests, route IDs,
prefixes, and scopes are validated; duplicates and unknown YAML fields fail
startup. A protected route is invalid when `api_keys` is empty. Configuration,
rotation, and revocation are restart-only; hot reload is not implemented.

### Rate-limit semantics

`rate_limit` is optional. If it is omitted, that route has no rate limiting.
When any route enables it, the top-level `redis` block is required.
Redis dial/command durations are bounded to ten seconds, and `pool_size`
explicitly caps the gateway's Redis connections (default 20, maximum 1000).

- `capacity` is the maximum number of tokens and therefore the maximum burst.
- `refill_per_second` is the number of tokens restored per second; positive
  decimal values are supported.
- Every allowed request consumes one token.
- `on_redis_error: deny` returns `503`; `allow` forwards the request while
  quota enforcement is unavailable. There is no implicit fail-open behavior.

Buckets start full and are independent per route. Authenticated routes use the
validated API-client ID. Public routes use the direct socket peer IP and never
trust forwarding headers. Raw subjects and credentials are not placed in Redis
keys. Redis server time is the shared clock, and one Lua operation atomically
refills, decides, consumes, and expires bucket state.

An exhausted bucket returns JSON `429` with `Retry-After` rounded up to whole
seconds until one token should be available. Inactive state expires after twice
the time needed to refill an empty bucket, between one second and 24 hours.

`/healthz` remains process-only liveness. `/readyz` returns `503` when Redis is
unavailable and at least one route uses fail-closed `deny`. A configuration
containing only fail-open policies remains ready during that outage.

### WAF semantics

`waf` is optional per route; omission means no inspection. Explicit
`mode: disabled` takes no rule set, threshold, inspection flags, or unused
limits. `audit` evaluates `core-v1`, publishes one bounded security event when a
rule matches, and forwards the request. `enforce` returns JSON `403` with code
`WAF_BLOCKED` when the summed score reaches `anomaly_threshold`. Thresholds
must be 1–100. Unknown fields, modes, and rule sets fail startup.

The active request order is route match, authentication/authorization, Redis
rate limiting, WAF inspection, then reverse proxy. Method and decoded path are
always represented. Enabled query inspection decodes percent escapes exactly
once, treats `+` as space, and preserves duplicate values separately. Header
inspection excludes credential and cookie values. Text must be valid UTF-8 and
must not contain NUL. Original URL, headers, and exact buffered body bytes are
unchanged for forwarding.

Body inspection supports `application/json`,
`application/x-www-form-urlencoded`, and `text/plain` with absent or UTF-8
charset. A non-empty inspected body with a missing or unsupported media type,
multipart content, unsupported charset, or compression returns `415`.
Malformed encodings or JSON return `400`; oversize bodies and excessive JSON
element counts return `413`. These hard parsing and resource limits also apply
in audit mode. Chunked bodies use the same hard byte limit. Multipart files are
not scanned.

Method and path have fixed 32-byte and 8 KiB inspection ceilings.
Configuration maxima are 64 KiB each for query and headers, 2 MiB for body,
JSON depth 64, and 10,000 JSON elements. `core-v1` contains six immutable,
startup-compiled rules (`AG-1001`–`AG-1006`) for selected strong SQLi, XSS,
traversal, command-injection, ambiguous-encoding, and method-override signals.
It does not join separate request fields or repeatedly decode values. See
[`ADR 0003`](docs/adr/0003-bounded-request-inspection.md) for the exact
normalization, scoring, failure, privacy, and limitation contract.

### Asynchronous security events and detection

When at least one route enables WAF inspection, AegisGate starts an in-memory
pipeline. The request path constructs an immutable bounded event and performs
a non-blocking publish to a bounded ingress queue. One detector goroutine owns
all correlation state, and a fixed worker pool writes raw events and generated
alerts to the structured `slog` sink through per-write timeouts. WAF parsing,
scoring, audit/enforce selection, and rejection remain synchronous.

Delivery is deliberately **best effort**: the pipeline is process-local,
non-durable, and able to drop the newest event when saturated or closing.
Delivery success never controls an HTTP decision. It is not a SIEM, message
broker, persistent audit log, or cross-instance correlation system. Periodic
and final summaries expose accepted, dropped, processed, alert, sink-error,
delivery, queue-depth, and active-key statistics. v0.6 adds no public metrics
endpoint.

`AG-D2001` counts each stable WAF rule ID independently by route. `AG-D2002`
counts block decisions by route. Both use fixed windows, exact thresholds,
one alert per key per window, cooldown suppression, server-generated time, and
a shared `max_keys` bound. A threshold crossed during cooldown does not alert
later in that same window. At the key bound, existing keys continue while new
keys are dropped and counted.
Detection resets on process restart.

`security_events` is optional when WAF is enabled; omission selects the values
shown above. An explicit block must be complete. Unknown, zero, negative,
excessive, contradictory, or unused settings fail startup. Maximums are 65,536
entries per queue, 64 workers, 10 seconds per sink write, 30 seconds for
pipeline shutdown, one hour for summaries/windows, 24 hours for cooldown,
1,000,000 for thresholds, and 65,536 active detector keys. The block is
rejected when no route enables WAF. Settings are startup-only and have no
environment-variable duplicates. See
[`ADR 0004`](docs/adr/0004-asynchronous-security-event-pipeline.md).

### Routing and timeouts

`/api/users` matches itself and `/api/users/42`, not `/api/users-v2`; the
longest valid match wins. `/` may be a catch-all. `/healthz` and `/readyz` are
reserved. Ambiguous non-canonical request paths containing dot segments,
duplicate separators, or backslashes are rejected instead of falling through
to a broader route. Incoming paths are preserved, while an upstream base path
is prepended using Go's reverse-proxy path joining.

Each route timeout must be strictly less than `server.write_timeout`, including
after environment overrides. A timeout before a response starts returns JSON
`504`. Once headers or body bytes have started streaming, HTTP cannot replace
the partial response with a JSON error; the connection may end partially.

## Generate and store keys

```bash
go run ./cmd/keygen
```

The command prints a high-entropy plaintext key once and its SHA-256 digest.
Give the plaintext to the client through a secret manager, then discard the
output. Copy only the digest into YAML. Never commit or log plaintext keys.

Committed example digests are deliberately non-working placeholders. Copy
`configs/config.example.yaml` to the gitignored `configs/local.yaml`, generate
two keys, and grant `orders:read` to only one to run the full demo.

### Migrate from v0.5

Existing v0.5 files remain valid. If any route enables WAF and
`security_events` is omitted, v0.6 starts the pipeline with conservative
defaults. Add the complete block above only to tune it. Log consumers must no
longer assume WAF events are emitted synchronously or in request-completion
order. Raw events use `aegis.security_event.v1`; alerts use
`aegis.security_alert.v1`. Restart all gateways after configuration changes.

## Run locally

Start Redis and two upstreams in separate terminals. For example, use your
local Redis installation on `localhost:6379`, then run:

```powershell
$env:EXAMPLE_SERVICE_NAME="users-upstream"
$env:EXAMPLE_HTTP_ADDR=":8081"
go run ./cmd/example-upstream
```

```powershell
$env:EXAMPLE_SERVICE_NAME="orders-upstream"
$env:EXAMPLE_HTTP_ADDR=":8082"
go run ./cmd/example-upstream
```

Start the gateway with the gitignored configuration:

```powershell
$env:AEGIS_CONFIG_PATH="configs/local.yaml"
go run ./cmd/gateway
```

```bash
curl -i http://localhost:8080/api/users/42
curl -i http://localhost:8080/api/orders/99
curl -i -H "X-API-Key: $LIMITED_API_KEY" http://localhost:8080/api/orders/99
curl -i -H "X-API-Key: $ORDERS_API_KEY" http://localhost:8080/api/orders/99
```

Expected statuses are `200`, `401`, `403`, and `200`. Health and readiness
remain public gateway-owned endpoints. Repeated public requests eventually
return `429`; the exact point depends on refill timing and configured capacity.

## Run with Docker

The default Compose file starts Redis without publishing its port. It
demonstrates public limiting and protected rejection; committed API-key digests
remain non-working placeholders. For authenticated demonstrations, keep
Compose service-name upstream URLs in gitignored `configs/local.yaml` and run:

```powershell
$env:AEGIS_CONFIG_FILE="./configs/local.yaml"
docker compose up --build
```

Only gateway port `8080` is published. Stop with `Ctrl+C` or
`docker compose down`.

Public exhaustion:

```powershell
1..7 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8080/api/users/42 }
```

For an authenticated route, send the valid local key four times against the
Docker demo policy (`capacity: 3`) to observe `200, 200, 200, 429`. A second
valid key with the same scope gets its own independent bucket.

To demonstrate two gateways sharing one bucket:

```powershell
docker compose --profile distributed-demo up --build
curl.exe -i http://localhost:8080/api/users/42
curl.exe -i http://localhost:8083/api/users/42
```

Alternate requests between ports `8080` and `8083`; together they exhaust the
single Redis bucket when both containers observe the same direct peer. The
deterministic cross-instance demonstration uses an authenticated client:

```powershell
$ports = @(8080, 8083, 8080, 8083)
$ports | ForEach-Object { curl.exe -s -o NUL -w "%{http_code}`n" -H "X-API-Key: $env:ORDERS_API_KEY" "http://localhost:$($_)/api/orders/42" }
```

With the Docker capacity of three, this prints `200, 200, 200, 429`. Generate a
second key, configure it with `orders:read`, restart, and send one request with
that key to see an independent `200`. Depending on Docker's NAT path, the direct
peer observed for public requests can differ between gateway containers; the
authenticated client ID is therefore the reproducible shared subject.

Failure behavior for the committed fail-closed demo:

```powershell
docker compose stop redis
curl.exe -i http://localhost:8080/readyz
curl.exe -i http://localhost:8080/api/users/42
```

Both return `503`; `/healthz` remains `200`. Change a route explicitly to
`on_redis_error: allow` to demonstrate forwarding during the outage.

The committed Docker configuration runs `users` in WAF audit mode and `orders`
in enforce mode. Its demonstration-only detector threshold is three. A benign
users request and repeated audit matches all reach the upstream; logs contain
asynchronous raw events followed by an `AG-D2001` alert:

```powershell
curl.exe -i "http://localhost:8080/api/users/42?q=hello"
1..3 | ForEach-Object { curl.exe -i "http://localhost:8080/api/users/42?q=1%27%20OR%201%3D1--" }
docker compose logs gateway | Select-String "aegis.security_event.v1|AG-D2001"
```

After placing a valid digest in a gitignored Docker configuration, the
equivalent protected orders request is blocked before its upstream:

```powershell
curl.exe -i -H "X-API-Key: $env:ORDERS_API_KEY" "http://localhost:8080/api/orders/42?q=1%27%20OR%201%3D1--"
```

Repeat that protected request three times to observe `AG-D2002`; every response
remains `403`. Stop the gateway gracefully and inspect its final counters:

```powershell
docker compose stop gateway
docker compose logs gateway | Select-String "security-event pipeline stopped"
```

## Security model

Authorization follows one route match and precedes upstream work. A protected
child cannot bypass policy through a public parent. `X-API-Key`, `Forwarded`,
arbitrary `X-Forwarded-*`, `X-Real-IP`, and client-supplied `X-Aegis-*` headers
are removed or rebuilt before proxying. AegisGate forwards no identity
assertion.

API keys are bearer credentials. Use TLS outside local development, distribute
keys securely, rotate them, and monitor use. Rate limiting does not prevent
DDoS attacks and does not replace user authorization. Public IP quotas group
users behind NAT and are not proxy-aware because no trusted-proxy model exists.
Invalid-key attempts are rejected before authenticated-client charging; a
separate direct-peer brute-force limiter is deferred. See
[`ADR 0001`](docs/adr/0001-api-client-key-trust-model.md),
[`ADR 0002`](docs/adr/0002-redis-token-bucket-rate-limiting.md), and
[`ADR 0003`](docs/adr/0003-bounded-request-inspection.md).

The WAF is intentionally small and signature-based. It is not OWASP CRS,
ModSecurity, an enterprise WAF, an IDS, malware scanning, or DDoS mitigation.
It cannot prove a request safe. Upstreams must still use parameterized SQL,
contextual output encoding, allowlist validation, safe process execution,
filesystem authorization, and resource-level authorization. Security events
never include API keys, authorization/cookie values, query strings, bodies,
raw evidence, arbitrary header values, client identity, or peer address.
They also exclude upstream or Redis credentials, internal error strings, and
stack traces.

## Checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Real Redis script tests require `AEGIS_REDIS_INTEGRATION_ADDR`, for example:

```powershell
$env:AEGIS_REDIS_INTEGRATION_ADDR="127.0.0.1:6379"
go test -count=1 -v ./internal/ratelimit
```

Make targets include `generate-key`, `fmt`, `tidy`, `check`, `test-race`,
`test-fuzz`, `bench-waf`, `bench-security-events`, and `build`. The measured
v0.5 WAF microbenchmark,
including environment and inputs, is recorded in
[`docs/benchmarks/v0.5-waf.md`](docs/benchmarks/v0.5-waf.md); v0.6 pipeline
microbenchmarks are in
[`docs/benchmarks/v0.6-security-events.md`](docs/benchmarks/v0.6-security-events.md).

## Workflow and roadmap

`main` is stable, `develop` is the integration branch, and feature branches
start from `develop`. Promote milestones only after validation and review.

| Milestone | Scope | Status |
| --- | --- | --- |
| v0.1 | Gateway foundation | Implemented |
| v0.2 | Configurable routing and timeouts | Implemented |
| v0.3 | API-client authentication and route authorization | Implemented |
| v0.4 | Redis-backed distributed rate limiting | Released (`v0.4.0`) |
| v0.5 | Bounded request inspection and WAF rules | Released (`v0.5.0`) |
| v0.6 | Asynchronous security events and process-local detection | Implemented on feature branch |
| v0.7 | Metrics, tracing, and operational observability | Planned |
| v0.8 | gRPC control plane and distributed configuration | Planned |

## License

No license has been selected. Until one is added, all rights are reserved.
