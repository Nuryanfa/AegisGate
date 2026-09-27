# AegisGate

AegisGate is a portfolio-grade API gateway and security platform written in
Go. v0.3 adds API-client authentication and route-scope authorization to the
strictly configured v0.2 gateway.

This is an educational, production-like project, not a claim of production
readiness. An API key identifies a calling application, not a human user.

## Capabilities

- Standard-library HTTP server and reverse proxy
- Strict, startup-only YAML configuration
- Boundary-aware longest-prefix routing and per-route deadlines
- Explicit public or API-key-protected routes
- SHA-256-only key registry with all-required scope authorization
- JSON `401`, `403`, `404`, `502`, and `504` errors
- Request IDs, structured logs, forwarding-header sanitization, health checks,
  graceful shutdown, and race-oriented tests
- Non-root image and three-service Compose demo

Go 1.25.x is required. Docker Compose is needed only for the container demo.

## Configuration

`AEGIS_CONFIG_PATH` selects one required YAML file. Routes and API-key digests
come only from this file. Server values use this precedence:

```text
environment variable -> YAML server value -> built-in default
```

Supported overrides are `AEGIS_ENV`, `AEGIS_HTTP_ADDR`,
`AEGIS_READ_TIMEOUT`, `AEGIS_WRITE_TIMEOUT`, `AEGIS_IDLE_TIMEOUT`, and
`AEGIS_SHUTDOWN_TIMEOUT`. Removed v0.1 variable `AEGIS_UPSTREAM_URL` is rejected.

```yaml
server:
  write_timeout: 15s

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

  - id: orders
    path_prefix: /api/orders
    upstream: http://localhost:8082
    timeout: 8s
    auth:
      mode: api_key
      required_scopes: [orders:read]
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

### Migrate from v0.2

Add an `auth` block to every existing route; choose `mode: public` to preserve
its previous open behavior. For routes that should be protected, choose
`mode: api_key`, declare at least one `required_scopes` entry, generate a key,
and add only its digest plus at least one scope under `api_keys`. Restart the
gateway after changing the file. An omitted mode intentionally fails startup.

## Run locally

Start two upstreams in separate PowerShell terminals:

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
remain public gateway-owned endpoints.

## Run with Docker

The default Compose file demonstrates public access and protected rejection;
its placeholder digests match no real key. For all outcomes, keep Compose
service-name upstream URLs in `configs/local.yaml` and run:

```powershell
$env:AEGIS_CONFIG_FILE="./configs/local.yaml"
docker compose up --build
```

Only gateway port `8080` is published. Stop with `Ctrl+C` or
`docker compose down`.

## Security model

Authorization follows one route match and precedes upstream work. A protected
child cannot bypass policy through a public parent. `X-API-Key`, `Forwarded`,
arbitrary `X-Forwarded-*`, `X-Real-IP`, and client-supplied `X-Aegis-*` headers
are removed or rebuilt before proxying. v0.3 forwards no identity assertion.

API keys are bearer credentials. Use TLS outside local development, distribute
keys securely, rotate them, and monitor use. v0.3 has no end-user identity,
expiry, automatic rotation, instant revocation, tenant isolation, ownership
checks, rate limiting, WAF, or remote control plane. Upstreams remain
responsible for user authorization. See
[`ADR 0001`](docs/adr/0001-api-client-key-trust-model.md).

## Checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Make targets include `generate-key`, `fmt`, `tidy`, `check`, `test-race`, and
`build`.

## Workflow and roadmap

`main` is stable, `develop` is the integration branch, and feature branches
start from `develop`. Promote milestones only after validation and review.

| Milestone | Scope | Status |
| --- | --- | --- |
| v0.1 | Gateway foundation | Implemented |
| v0.2 | Configurable routing and timeouts | Implemented |
| v0.3 | API-client authentication and route authorization | Implemented on feature branch |
| v0.4 | Bounded rate limiting with explicit failure behavior | Next |
| v0.5–v0.8 | WAF, detection, observability, distributed deployment | Planned |

## License

No license has been selected. Until one is added, all rights are reserved.
