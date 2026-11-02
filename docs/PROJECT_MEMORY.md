# AegisGate Project Memory

Last updated: 2026-11-02

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
- Data-plane protocol: plaintext HTTP. The gateway has no in-process TLS
  listener yet, so HTTPS must be terminated by a trusted component in front of
  it. WebSocket proxying is a PRD goal but is not yet an explicitly specified
  and tested contract. gRPC is used only for the v0.8 control-plane stream;
  the gateway does not proxy gRPC traffic.
- AegisGate is an educational engineering showcase, not a replacement for
  Kong, Envoy, NGINX, a full enterprise WAF, SIEM, IDS, or DDoS scrubbing.
- The data plane should remain stateless where practical. Shared runtime state
  uses Redis. Durable control-plane data may later use PostgreSQL; no
  PostgreSQL dependency exists as of v0.8.
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
API-client access control, and v0.4 added Redis-backed distributed rate
limiting. v0.5 added bounded request inspection and a small WAF rule foundation.
v0.6 replaced synchronous WAF-event logging with a bounded asynchronous
pipeline and deterministic process-local burst detection. v0.7 added
Prometheus metrics, OpenTelemetry tracing, and operational documentation.
v0.8 added a single-authority gRPC control plane with atomic runtime swaps.

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
- Audit matches are published and forwarded; enforce matches at threshold return
  `403`. Hard input/limit errors remain `400`, `413`, or `415`. Unexpected
  internal errors fail closed in enforce and fail open with a safe warning in
  audit.
- Security logs contain stable metadata, never credentials, payloads, query
  strings, arbitrary headers, raw evidence, client identity, or peer address.
- The threat model and normalization contract are recorded in ADR 0003. This
  milestone makes no enterprise-WAF, complete prevention, IDS, or DDoS claim.

## Confirmed v0.6 asynchronous security-event foundation

- WAF enforcement remains synchronous. Only event correlation and delivery are
  asynchronous, and their success never changes an HTTP decision.
- The request path publishes immutable bounded metadata without waiting for
  capacity. A lifecycle read/write lock makes concurrent publish and channel
  closure safe. Full or closing ingress uses drop-newest and increments a
  counter.
- A single detector goroutine owns bounded fixed-window state. `AG-D2001`
  counts stable rule IDs per route and `AG-D2002` counts blocks per route.
  Each key emits at most once per window at its exact threshold crossing;
  cooldown can suppress a whole window. At `max_keys`, expired entries are
  reclaimed and otherwise new keys are dropped while existing keys continue.
- Detector output enters a second bounded queue. A fixed worker pool invokes a
  narrow sink with per-write timeouts. Failures are counted and do not stop
  workers; v0.6 has no retry or external broker.
- The structured-log sink uses an explicit allowlist. Events and alerts contain
  no credentials, payloads, query strings, raw evidence, arbitrary headers,
  identities, addresses, internal errors, or request-owned objects.
- Shutdown occurs only after HTTP drain, then closes publication, drains the
  detector and workers within a separate deadline, cancels outstanding sink
  calls on timeout, allows a bounded cancellation grace period, and emits final
  internal statistics only after every pipeline goroutine exits. If a sink
  ignores cancellation, shutdown returns with a distinct diagnostic instead
  of claiming the pipeline has stopped.
- The pipeline is best effort, in-memory, process-local, non-durable, and may
  lose events under saturation, shutdown timeout, process failure, or sink
  failure. It is not a SIEM or cross-instance detector. ADR 0004 records this
  architecture and its rejected alternatives.

## Confirmed v0.7 operational-observability foundation

- `observability` is optional; omitted means metrics and tracing are off and
  v0.6 configuration remains valid. The block is file-only.
- Native Prometheus metrics use a private registry (project, Go, process
  collectors) and a read-only collector over the v0.6 pipeline snapshot. They
  are not duplicated through OpenTelemetry.
- Metrics are served on a dedicated listener with an exact path and explicit
  timeouts. Compose does not publish it on the public gateway port. A listener
  bind or unexpected termination fails the process.
- Labels are route IDs from validated configuration plus finite enums. No
  request/trace IDs, URLs, query strings, API identities, client addresses,
  WAF evidence, arbitrary headers, or raw errors become labels. Latency
  histograms span 1 ms to 10 s.
- Tracing uses the OpenTelemetry SDK with parent-based ratio sampling, a
  bounded batch queue, OTLP HTTP export, and W3C TraceContext only. One server
  span per request, internal spans for rate-limit and WAF checks, and one
  upstream client span. Disabled tracing creates no exporter or worker.
- Client-supplied trace headers are always stripped before proxying. With
  tracing enabled, only the active `traceparent` is injected; client
  `tracestate` is discarded and baggage is never forwarded.
- Exporter failures never change security decisions or readiness; buffered
  spans may be lost. Shutdown drains gateway HTTP, then telemetry HTTP, then
  the security-event pipeline, then flushes the trace provider.
- Static build metadata (`VERSION`, `COMMIT`, `BUILD_TIME`) is supplied as
  Docker build arguments and exposed via startup logs and
  `aegisgate_build_info`.
- The Compose `observability` profile (Prometheus, OTel Collector, Jaeger,
  Grafana) is a non-durable demo. SLIs/SLOs are illustrative, not measured.
  ADR 0005 records the decision.

## Confirmed v0.8 gRPC control-plane foundation

- One in-memory writable authority (`cmd/control-plane`) loads a strict YAML
  snapshot from `AEGIS_CONTROL_PLANE_CONFIG_PATH`, refuses startup without a
  valid initial snapshot, and reloads only on `SIGHUP`. There is no file
  polling, persistent history, consensus, HA, admin API, or rollback.
- `api/controlplane/v1/configuration.proto` defines the bidirectional
  `ConfigurationService.Sync` stream. Generated Go code is committed, produced
  by Buf, and never hand-edited; CI checks generation and breaking changes
  against `origin/main`.
- Snapshots carry only routes, policy values, API-client IDs, SHA-256 digests,
  and scopes. Listeners, Redis credentials, TLS keys, telemetry settings, and
  security-event capacity remain node-local and restart-only.
- Revisions are canonical SHA-256 content hashes (sorted routes, clients, and
  scopes; deterministic marshaling). Stream sequence restarts at 1 per stream
  and is independent of content identity.
- Gateways validate, check local capabilities, compile a complete immutable
  runtime, publish it with one `atomic.Pointer` store, and then ACK. An
  unchanged revision is ACKed without recompilation. Failures keep the prior
  runtime and send a sanitized NACK (`validation`, `dependency`, `protocol`).
- Requests load the runtime pointer once; in-flight requests finish on the
  runtime they selected. No global mutex sits in request dispatch.
- The authority bounds connections and streams with `max_clients` and keeps
  one latest-wins pending slot per stream. Gateways run one reconnect
  supervisor with exponential backoff and up to 25% jitter.
- `control_plane` absent preserves v0.7 behavior. `require_remote` returns
  `503 CONFIG_NOT_READY` until a remote revision is accepted;
  `use_bootstrap` serves local routes immediately.
- Heartbeats arrive every 30s; `stale_after` is at least 1m. Freshness uses
  the last valid snapshot or heartbeat, not the last configuration change.
  `stale_policy: deny` returns `503 CONFIG_STALE` and fails readiness;
  `serve` keeps the last-known-good runtime.
- Production requires mTLS on both sides (TLS 1.2+); plaintext gRPC is allowed
  only in explicit development mode, as in the Compose demo.
- Route metric series admit at most 64 distinct route IDs per process; later
  IDs map to `_other`. ADR 0006 and `docs/control-plane.md` record the
  protocol and failure contracts.

## Critical engineering observations

- “10,000+ requests/second” and latency targets are hypotheses until the test
  environment and scenario are defined. They must not be presented as achieved
  results without reproducible evidence. *Still open: only narrow
  microbenchmarks exist (v0.5–v0.8); no end-to-end load test has been run.*
- A regex-only WAF is useful as an educational component but is bypass-prone
  and can cause false positives or regex denial of service. Rules need bounded
  input, normalization policy, safe regexes, audit mode, and bypass tests.
  *Addressed for `core-v1` in v0.5 (ADR 0003).*
- Distributed token-bucket behavior in Redis needs atomic operations, normally
  via Lua or an equivalent atomic primitive, plus a declared fail-open/fail-
  closed policy for Redis outages. *Addressed in v0.4 (ADR 0002).*
- Client-IP rate limiting is unsafe until trusted proxies and `Forwarded` /
  `X-Forwarded-For` handling are specified. *Still open: public quotas use
  the direct socket peer only.*
- An in-memory Go channel is not durable. Queue saturation, drop/backpressure
  policy, shutdown draining, and event-loss metrics must be explicit.
  *Addressed in v0.6/v0.7 (ADR 0004, ADR 0005); events remain non-durable.*
- Authentication requires issuer, audience, algorithm allowlist, key rotation,
  clock skew, and JWKS/static-key decisions; “validate JWT” alone is
  insufficient. *Still open: JWT is not implemented.*
- Route configuration needs deterministic precedence, path rewrite semantics,
  config validation, and an atomic reload strategy. *Addressed in v0.2
  (precedence, validation) and v0.8 (atomic remote reload).*
- Retries can duplicate side effects. The default should be no retry unless the
  method and failure mode are proven safe. *Current behavior: no retries.*
- Control plane and data plane separation should be conceptual first; splitting
  them into deployable services too early would add complexity before value.
  *v0.8 split them deliberately while keeping the control plane off the
  request path.*
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

- License and intended reuse policy. Until chosen, all rights are reserved.
- Scope of the next milestone after v0.8 (see the PRD backlog below).
- JWT trust model: issuer, audience, algorithm allowlist, key source
  (static vs. JWKS), rotation, and clock skew.
- Trusted-proxy model for deriving client IPs from `Forwarded` /
  `X-Forwarded-For`.
- Whether WebSocket proxying becomes an explicit, tested contract, and how it
  interacts with WAF body inspection and route deadlines.

Resolved since the original list:

- Repository and module path: `github.com/Nuryanfa/AegisGate`.
- Development baseline: Go 1.25.x with Docker Compose demos.
- First vertical slice: delivered as Sprint 0/v0.1.
- Configuration contract: strict YAML with restart (v0.2), plus validated
  remote snapshots with atomic swap when `control_plane` is set (v0.8).
- Redis outage policy: explicit per-route `deny` or `allow` (v0.4).

## PRD backlog not yet implemented

These PRD items have no accepted design yet. Each needs its own scoped
milestone and ADR before implementation:

- JWT authentication and role-based authorization.
- In-process HTTPS listener with certificate management for the data plane.
- Upstream health checks, load balancing across replicas, circuit breaking,
  and idempotency-aware retries.
- Trusted-proxy client-IP model and invalid-key abuse limiting.
- Explicit WebSocket support.
- Admin API, PostgreSQL persistence, and durable configuration history.
- Real-time dashboard and WebSocket event streaming.
- External event broker (NATS/Kafka) and cross-instance detection.
- Kubernetes manifests and Terraform.
- End-to-end load testing, profiling, and chaos testing.

## Confirmed facts

- Working project name: AegisGate.
- Existing product document: `PRD.md`, version 1.0, status Planning. It is a
  vision document; this file and accepted ADRs record what is actually built.
- Git remote: `github.com/Nuryanfa/AegisGate`. Release tags `v0.1.0` through
  `v0.8.0` exist on the remote.
- The directory was not a Git repository when first inspected on 2026-09-27.

## Branching strategy

- `main` is the stable release branch. Only reviewed changes that pass the
  required quality gates should be merged into it.
- `develop` is the integration branch for ongoing milestone development.
- Short-lived feature and fix branches should start from `develop` and return
  through pull requests.
- A completed milestone is promoted from `develop` to `main` after tests,
  documentation, container validation, and review are complete.
- As of 2026-11-02, `main` and `develop` are synchronized. `main` is ahead of
  the `v0.8.0` tag only by documentation and CI changes (README/memory
  refresh and the Buf breaking-check fix); no unreleased code exists.

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
- 2026-10-02: Started v0.6 from released `v0.5.0` on
  `feature/v0.6-security-event-pipeline`. Selected bounded drop-newest ingress,
  a single-owner detector, bounded delivery with fixed workers, and a timed
  allowlisted slog sink; recorded the decision in ADR 0004.
- 2026-10-02: `v0.6.0` is released on `main`; fast-forwarded `develop` to the
  release and began v0.7 on `feature/v0.7-observability`. Selected native
  Prometheus pull metrics with a private registry and separate listener,
  read-only v0.6 pipeline snapshot collection, and OpenTelemetry traces via
  bounded OTLP HTTP batching and W3C propagation. Telemetry exporter failure
  does not change security decisions or readiness. ADR 0005 records the scope.
- 2026-10-02: v0.7 review hardening: remove raw trace headers unconditionally
  before proxying, inject active trace context only when tracing is enabled,
  and pass bounded static build metadata into Docker gateway images.
- 2026-10-03: Released AegisGate v0.7.0 with Prometheus metrics, OpenTelemetry
  tracing, a dedicated telemetry listener, trace-safe reverse-proxy
  propagation, operational dashboards, alert rules, and static build metadata.
- 2026-10-03: Began v0.8 on `feature/v0.8-grpc-control-plane` after synchronizing
  `develop` with the v0.7 release commit. Selected one in-memory authority,
  typed gRPC streams, canonical content revisions, bounded latest-wins fan-out,
  node-local secrets and dependencies, and immutable atomic gateway runtimes.
  Development-only insecure Compose transport and production mTLS are explicit;
  ADR 0006 records the decision.
- 2026-10-03: Corrected v0.8 freshness to use the last authenticated valid
  snapshot or heartbeat, independently of the last accepted snapshot time.
  Enforced a minimum 1m stale deadline for the 30s heartbeat cadence, added
  explicit gRPC TraceContext transport instrumentation, and finalized the
  v0.7 release wording in the README.
- 2026-10-03: Released AegisGate v0.8.0 on `main` with the single-authority
  gRPC control plane, atomic gateway runtime publication, mTLS contract,
  freshness-aware heartbeat handling, and transport-level trace propagation.
- 2026-10-03: On `develop`, refreshed the README as a v0.8 portfolio showcase
  and changed CI to run `buf breaking` against the remote `main` branch.
- 2026-11-02: Refreshed this memory: added confirmed v0.7 and v0.8 sections,
  annotated which critical observations are addressed, resolved obsolete open
  decisions, and recorded the unimplemented PRD backlog. No new scope was
  accepted.
