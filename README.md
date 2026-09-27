# 🛡️ AegisGate

### A security-first API gateway engineered in Go

AegisGate is a portfolio-grade, cloud-native API gateway and security platform
built primarily in Go. The project develops each capability as a small, tested
milestone and documents the engineering trade-offs along the way.

> **Status:** Sprint 0 (`v0.1`) Gateway Foundation is implemented and validated
> on `main`. Active milestone development continues on `develop`.

[Product requirements](PRD.md) · [Engineering notes](docs/PROJECT_MEMORY.md) ·
[Roadmap](#roadmap)

## Why AegisGate?

Applications with several backend services need a consistent entry point for
routing, request correlation, traffic controls, and security policies.
AegisGate is a hands-on exploration of that edge layer, beginning with a
working reverse proxy and expanding through later security and observability
milestones.

```mermaid
flowchart LR
    C["Client"] --> G["AegisGate"]
    G --> A["Service A"]
    G --> B["Service B"]
```

AegisGate is an engineering portfolio project. It is not an enterprise WAF,
SIEM, or drop-in replacement for an established gateway.

## Engineering focus

- **Go networking:** HTTP lifecycle, routing, and reverse proxying
- **Security:** explicit trust boundaries, safe errors, and testable assumptions
- **Reliability:** timeouts, graceful shutdown, and upstream failure handling
- **Operations:** containers, CI, structured logs, and reproducible validation

## Sprint 0 capabilities

- Explicitly configured `http.Server`
- Deterministic exact and longest-prefix route matching
- Reverse proxying with `net/http/httputil`
- Cryptographically random or client-preserved request IDs
- Structured request logging with `log/slog`
- Liveness and readiness endpoints
- Consistent JSON gateway errors
- Graceful `SIGINT` and `SIGTERM` shutdown
- Unit and integration-style proxy tests
- Minimal, non-root Docker images and a two-service Compose demo
- GitHub Actions validation

## Requirements

- Go 1.25.x
- Docker with Compose for the containerized demo
- `make` is optional; every target maps to a documented Go command

## Project structure

```text
cmd/
  gateway/           AegisGate process and dependency composition
  example-upstream/  Small backend used for the end-to-end demo
internal/
  config/            Environment parsing and validation
  middleware/        Request ID and request logging middleware
  proxy/             Reverse proxy dispatch and gateway errors
  router/            Deterministic route matching
  server/            HTTP server lifecycle and health handlers
configs/              Future file-config shape (not loaded in Sprint 0)
deployments/docker/   Multi-stage, non-root container build
```

## Configuration

Sprint 0 reads configuration from environment variables. Defaults are suitable
for running both processes directly:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AEGIS_ENV` | `development` | Text logs in development; JSON otherwise |
| `AEGIS_HTTP_ADDR` | `:8080` | Gateway listen address |
| `AEGIS_READ_TIMEOUT` | `10s` | Request read timeout |
| `AEGIS_WRITE_TIMEOUT` | `15s` | Response write timeout |
| `AEGIS_IDLE_TIMEOUT` | `60s` | Keep-alive idle timeout |
| `AEGIS_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline |
| `AEGIS_UPSTREAM_URL` | `http://localhost:8081` | Example route upstream |

Invalid durations, unsupported upstream schemes, missing upstream hosts, and
upstream URLs containing credentials cause startup to fail. See
[`.env.example`](.env.example) for a copyable local configuration.

## Running locally

Start the example upstream in one terminal:

```bash
go run ./cmd/example-upstream
```

Start the gateway in another terminal:

```bash
go run ./cmd/gateway
```

Then exercise the gateway:

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
curl -i http://localhost:8080/api/test/hello
```

The proxied response includes `X-Request-ID`. Supplying the header yourself
preserves the value:

```bash
curl -i -H 'X-Request-ID: demo-123' http://localhost:8080/api/test/hello
```

## Running with Docker

```bash
docker compose up --build
```

Compose starts only `gateway` and `example-upstream`. The gateway reaches the
backend through `http://example-upstream:8081`; only port `8080` is published to
the host.

Stop the stack with `Ctrl+C` or:

```bash
docker compose down
```

## Available endpoints

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/healthz` | Process liveness, returning `{"status":"ok"}` |
| `GET` | `/readyz` | Gateway readiness, returning `{"status":"ok"}` |
| Any | `/api/test/*` | Proxies the unchanged path to the example upstream |

Unmatched paths return a JSON `404`. Unreachable upstreams return a JSON `502`
without exposing the internal transport error.

## Architecture flow

```text
client
  -> request ID middleware
  -> structured request logging
  -> health/readiness or longest-prefix route match
  -> reverse proxy (sanitized forwarding headers)
  -> example-upstream
```

Client-provided `Forwarded` and `X-Forwarded-*` values are not trusted. The
proxy rebuilds `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
from the connection observed by AegisGate. The upstream receives its own host
in `Host` and the original public host in `X-Forwarded-Host`.

## Testing and checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Or use the convenience targets:

```bash
make fmt
make tidy
make check
make test-race
make build
```

## Development workflow

- `main` is the stable branch and contains only reviewed, validated code.
- `develop` is the integration branch for the next milestone and ongoing work.
- Create short-lived feature branches from `develop`, then merge them back
  through pull requests after CI passes.
- Promote `develop` to `main` only when the milestone definition of done is met.

## Roadmap

| Milestone | Scope | Status |
| --- | --- | --- |
| v0.1 · Gateway Foundation | HTTP server, prefix routing, proxy, request IDs, logging, health, tests, Docker, and CI | Implemented |
| v0.2 · Configurable Routing | Declarative routes, validation, route settings, and policy metadata | Next |
| v0.3 · Authentication | Identity and API access controls | Planned |
| v0.4 · Rate Limiting | Distributed traffic controls | Planned |
| v0.5 · WAF | Request inspection and rule evaluation | Planned |
| v0.6 · Detection | Security events and detection workflows | Planned |
| v0.7 · Observability | Metrics, traces, and operational visibility | Planned |
| v0.8 · Distributed Deployment | Deployment and resilience across instances | Planned |

Milestone details and proposed requirements live in [PRD.md](PRD.md). Roadmap
entries are goals, not claims that unimplemented features already work.

## Current limitations

Sprint 0 intentionally has one environment-configured example route and no
runtime configuration reload. It does not include a database, Redis,
authentication, authorization, rate limiting, WAF rules, durable event queues,
an observability stack, WebSocket-specific policy, a control plane, or a
frontend. TLS termination and trusted-proxy topology are also deployment
concerns not configured in this milestone.

## Principles

1. Ship a working vertical slice before expanding the platform.
2. Prefer the Go standard library when it meets the requirement.
3. Test routing, proxy behavior, failures, and concurrency as features arrive.
4. Separate implemented capabilities from future plans.
5. Publish performance claims only with a reproducible benchmark and environment details.

## Next milestone

The next logical milestone is **v0.2 — Configurable Routing and Gateway Policy
Foundation**. It should introduce validated multi-route configuration and clear
policy attachment points without implementing the later security platform.

## License

No license has been selected yet. Until a license is added, all rights are
reserved by the repository owner.
