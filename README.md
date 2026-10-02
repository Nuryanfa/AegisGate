# AegisGate

AegisGate is a portfolio-grade API gateway and security platform written in
Go. v0.5 adds bounded per-route request inspection and a small auditable WAF
rule engine to the authenticated, distributed-rate-limited v0.4 gateway.

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
limits. `audit` evaluates `core-v1`, logs one bounded security event when a
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

### Migrate from v0.4

Existing v0.4 files remain valid and have no WAF inspection. Add a complete
per-route `waf` block to opt in. Roll out `disabled -> audit -> review false
positives -> tune threshold or route policy -> enforce`. Restart all gateways
after changing policy; configuration is still startup-only.

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
in enforce mode. A benign users request and a representative audit match both
reach the users upstream; the match produces a metadata-only gateway event:

```powershell
curl.exe -i "http://localhost:8080/api/users/42?q=hello"
curl.exe -i "http://localhost:8080/api/users/42?q=1%27%20OR%201%3D1--"
```

After placing a valid digest in a gitignored Docker configuration, the
equivalent protected orders request is blocked before its upstream:

```powershell
curl.exe -i -H "X-API-Key: $env:ORDERS_API_KEY" "http://localhost:8080/api/orders/42?q=1%27%20OR%201%3D1--"
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
`test-fuzz`, `bench-waf`, and `build`. The measured v0.5 WAF microbenchmark,
including environment and inputs, is recorded in
[`docs/benchmarks/v0.5-waf.md`](docs/benchmarks/v0.5-waf.md).

## Workflow and roadmap

`main` is stable, `develop` is the integration branch, and feature branches
start from `develop`. Promote milestones only after validation and review.

| Milestone | Scope | Status |
| --- | --- | --- |
| v0.1 | Gateway foundation | Implemented |
| v0.2 | Configurable routing and timeouts | Implemented |
| v0.3 | API-client authentication and route authorization | Implemented |
| v0.4 | Redis-backed distributed rate limiting | Released (`v0.4.0`) |
| v0.5 | Bounded request inspection and WAF rules | Implemented on feature branch |
| v0.6–v0.8 | Detection, observability, distributed deployment | Planned |

## License

No license has been selected. Until one is added, all rights are reserved.
