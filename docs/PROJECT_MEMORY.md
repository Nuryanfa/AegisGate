# AegisGate Project Memory

Last updated: 2026-09-27

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
CI. Its single environment-configured route was replaced by v0.2. The next
planned milestone is v0.3 — Authentication and Authorization Foundation.

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
