# AegisGate Project Memory

Last updated: 2026-09-29

This file is the durable working memory for the repository. It summarizes the
current understanding of `PRD.md`; it does not silently turn proposals into
decisions. Update it whenever a material requirement or decision changes.

## Mission

Build a portfolio-grade, production-like API gateway and security platform in
Go that demonstrates networking, concurrency, distributed systems, security,
observability, testing, and operational engineering.

The portfolio narrative is not “a CRUD API in Go.” The intended evidence is a
measured and documented edge service with reverse proxying, policy enforcement,
asynchronous security events, resiliency, and telemetry.

## Product boundaries

- Primary language: Go.
- Initial protocols: HTTP/HTTPS and WebSocket; gRPC is later scope.
- AegisGate is an educational engineering showcase, not a replacement for
  Kong, Envoy, NGINX, a full enterprise WAF, SIEM, IDS, or DDoS scrubbing.
- The data plane should remain stateless where practical. Shared runtime state
  may use Redis; durable control-plane data may use PostgreSQL.
- Security-event processing should be asynchronous, but enforcement decisions
  that must block a request necessarily remain in the synchronous request path.

## Confirmed Sprint 0 vertical slice

The PRD contains ten roadmap phases. Sprint 0 deliberately delivers one
demonstrable slice:

1. One gateway binary using `net/http` and `httputil.ReverseProxy`.
2. Static YAML configuration with exact/prefix route matching.
3. Request ID, structured logging, panic recovery, and secure timeout defaults.
4. One or two local mock upstreams.
5. Health/readiness endpoints and graceful shutdown.
6. Unit and integration tests for routing, proxy behavior, cancellation, body
   limits, and failure responses.
7. Docker Compose demo and a reproducible baseline benchmark.

JWT, Redis rate limiting, WAF, control plane, persistent database, dashboard,
Kubernetes, and Terraform remain excluded and must be added only as separate
verified increments.

Sprint 0 established Go 1.25, standard-library HTTP and reverse-proxy
components, a non-root distroless container, Docker Compose, and GitHub Actions
CI. Its single environment-configured route was replaced by v0.2, v0.3 added
API-client access control, and v0.4 adds Redis-backed distributed rate
limiting. v0.5 adds bounded request inspection and a small WAF rule foundation.

## Confirmed v0.2 routing foundation

- `AEGIS_CONFIG_PATH` selects a required strict YAML file at startup; hot reload
  is outside v0.2.
- Route definitions have a single source of truth: the YAML file. Environment
  variables override only server settings using defaults < file < environment.
- `AEGIS_UPSTREAM_URL` is rejected with a migration message rather than being
  silently ignored.
- Route prefixes are canonical, boundary-aware, unique, and evaluated longest
  first. `/` is an explicit catch-all; health and readiness stay reserved.
- Incoming paths are preserved. An upstream base path is prepended using the
  standard reverse-proxy join behavior.
- Every route has a positive timeout. A route-owned deadline returns JSON 504;
  client cancellation does not cause the gateway to manufacture a new error.
- No inert policy or `auth_required` field exists. Policy schema is deferred
  until a milestone implements real enforcement.
- YAML parsing uses the single focused dependency `go.yaml.in/yaml/v3`.

## Confirmed v0.3 API-client access-control foundation

- Every configured route explicitly selects `public` or `api_key`; omitted or
  contradictory policy fails startup.
- Protected routes accept exactly one `X-API-Key` header. Query parameters,
  duplicate values, malformed values, and oversized values are rejected.
- Configuration stores only SHA-256 digests and scopes. The static registry is
  immutable after startup, compares digests in constant time across all keys,
  and requires all route scopes.
- This is application/client authentication, not end-user authentication.
  Upstream services retain responsibility for resource-level user access.
- Route matching happens once before authorization. More-specific protected
  routes cannot fall through to public parent prefixes.
- Credentials and client-supplied `X-Aegis-*` identity headers never reach an
  upstream. v0.3 emits no gateway identity assertion.
- Key rotation and revocation require a restart. TLS and secure external secret
  distribution are mandatory operational controls outside local development.
- Route timeouts must be strictly below the server write timeout. A timeout
  cannot be converted to JSON 504 after a response has already started.
- The trust model and its tradeoffs are recorded in ADR 0001.

## Confirmed v0.4 distributed rate-limiting foundation

- `rate_limit` is optional per route; omission plainly means unlimited by
  AegisGate. Enabled policies require explicit capacity, refill rate, and Redis
  failure behavior.
- One Redis Lua operation atomically reads, refills, decides, consumes, stores,
  and expires a bucket. Redis `TIME` is the shared clock and negative elapsed
  time is clamped to zero.
- Quotas are independent per route. Authenticated routes use validated API
  client IDs; public routes use direct peer IPs without trusting forwarding
  headers. Bounded hashes, not raw subjects or credentials, form Redis keys.
- `deny` returns 503 on Redis failure and makes Redis a readiness dependency.
  Explicit `allow` temporarily suspends enforcement and keeps readiness green
  when no fail-closed route exists.
- Exhaustion returns JSON 429 and an integer `Retry-After`. Rejections happen
  before upstream contact.
- Public peer-IP quotas have NAT and reverse-proxy limitations. Invalid-key
  abuse limiting remains a focused follow-up and no DDoS-prevention claim is
  made.
- The algorithm and trust boundary are recorded in ADR 0002. Real Redis script
  tests run in CI, including cross-client concurrency with no over-admission.

## Confirmed v0.5 bounded WAF foundation

- `waf` is optional per route. Explicit `disabled`, `audit`, and `enforce`
  modes do not imply protection when omitted or disabled.
- Authentication and distributed rate limiting precede inspection. A rejected
  credential or exhausted quota does not incur body-inspection work.
- `core-v1` has six immutable, startup-compiled rules with stable IDs,
  anomaly scores, auditable descriptions, and documented limitations. YAML
  cannot inject regular expressions or executable matchers.
- Query, headers, body size, JSON depth/elements, and canonical value count are
  bounded. Text is validated as UTF-8 without NUL and percent encoding is
  decoded exactly once.
- JSON, URL-encoded form, and plain text are the only inspected body types.
  Non-empty bodies without a supported type, multipart bodies, and compressed
  bodies are rejected. Exact buffered bytes are restored before proxying.
- Audit matches are logged and forwarded; enforce matches at threshold return
  `403`. Hard input/limit errors remain `400`, `413`, or `415`. Unexpected
  internal errors fail closed in enforce and fail open with a safe warning in
  audit.
- Security logs contain stable metadata, never credentials, payloads, query
  strings, arbitrary headers, raw evidence, client identity, or peer address.
- The threat model and normalization contract are recorded in ADR 0003. This
  milestone makes no enterprise-WAF, complete prevention, IDS, or DDoS claim.

## Critical engineering observations

- “10,000+ requests/second” and latency targets are hypotheses until the test
  environment and scenario are defined. They must not be presented as achieved
  results without reproducible evidence.
- A regex-only WAF is useful as an educational component but is bypass-prone
  and can cause false positives or regex denial of service. Rules need bounded
  input, normalization policy, safe regexes, audit mode, and bypass tests.
- Distributed token-bucket behavior in Redis needs atomic operations, normally
  via Lua or an equivalent atomic primitive, plus a declared fail-open/fail-
  closed policy for Redis outages.
- Client-IP rate limiting is unsafe until trusted proxies and `Forwarded` /
  `X-Forwarded-For` handling are specified.
- An in-memory Go channel is not durable. Queue saturation, drop/backpressure
  policy, shutdown draining, and event-loss metrics must be explicit.
- Authentication requires issuer, audience, algorithm allowlist, key rotation,
  clock skew, and JWKS/static-key decisions; “validate JWT” alone is
  insufficient.
- Route configuration needs deterministic precedence, path rewrite semantics,
  config validation, and an atomic reload strategy.
- Retries can duplicate side effects. The default should be no retry unless the
  method and failure mode are proven safe.
- Control plane and data plane separation should be conceptual first; splitting
  them into deployable services too early would add complexity before value.
- PostgreSQL should not sit in the gateway request path for ordinary routing or
  authentication decisions.

## Quality bar

- Race-safe code (`go test -race` where supported), deterministic tests, and no
  unbounded goroutine creation.
- Explicit server, upstream, idle, header, and shutdown timeouts.
- Structured logs with secret/token redaction.
- Metrics with controlled label cardinality; never use raw path, user ID, API
  key, or source IP as an unbounded metric label.
- Threat model and ADRs evolve alongside implementation.
- Performance reports disclose hardware, environment, scenario, duration,
  concurrency, payload, configuration, and errors.

## Open decisions

These must be confirmed before repository scaffolding hardens them:

- GitHub owner/organization, repository name, and public/private visibility.
- Go module path (normally tied to the GitHub repository URL).
- License and intended reuse policy.
- Whether the recommended first vertical slice is the agreed MVP.
- Supported development baseline: Go version and whether Docker Desktop/WSL2
  is available on the primary machine.
- Initial configuration contract: YAML-only with restart, or hot reload.
- JWT trust model and Redis outage policy for later phases.

## Confirmed facts

- Working project name: AegisGate.
- Existing product document: `PRD.md`, version 1.0, status Planning.
- Git is installed locally.
- The directory was not a Git repository when first inspected on 2026-09-27.

## Branching strategy

- `main` is the stable release branch. Only reviewed changes that pass the
  required quality gates should be merged into it.
- `develop` is the integration branch for ongoing milestone development.
- Short-lived feature and fix branches should start from `develop` and return
  through pull requests.
- A completed milestone is promoted from `develop` to `main` after tests,
  documentation, container validation, and review are complete.

## Decision log

- 2026-09-27: Created durable repository memory and engineering guardrails.
  No architecture proposal in the PRD was treated as final without explicit
  confirmation.
- 2026-09-27: Confirmed and implemented the Sprint 0/v0.1 gateway-core scope.
  Kept future security, persistence, messaging, observability, orchestration,
  and frontend features outside this milestone.
- 2026-09-27: Adopted a stable `main` plus integration `develop` branching
  strategy for subsequent milestones.
- 2026-09-27: Implemented the v0.2 configurable routing foundation on
  `develop`, including strict YAML, multi-route matching, and route deadlines.
- 2026-09-28: Implemented the v0.3 API-client authentication and route-scope
  authorization foundation on `feature/v0.3-api-client-auth`, using digest-only
  static keys and explicit public/protected route policies.
- 2026-09-28: Implemented the v0.4 Redis-backed distributed token bucket on
  `feature/v0.4-distributed-rate-limiting`, with atomic Lua enforcement,
  subject hashing, explicit outage policy, and fail-closed readiness.
- 2026-09-29: Synchronized `develop` with released tag `v0.4.0` and started
  v0.5 on `feature/v0.5-bounded-waf`. Added bounded per-route inspection,
  audit/enforce scoring, privacy-safe events, and ADR 0003.
