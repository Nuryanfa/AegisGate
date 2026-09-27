# ADR 0001: API client key trust model

Status: Accepted

Date: 2026-09-28

## Context

AegisGate v0.3 needs route-level authentication and authorization without a
database or remote control plane. This control identifies calling applications,
not human end users. API keys are bearer credentials: anyone who obtains one
can use all scopes granted to it.

The gateway must reject ambiguous credential transport, avoid storing
plaintext credentials, keep secrets out of logs and upstream requests, and
remain safe under concurrent request handling.

## Options considered

1. Store plaintext keys in YAML and compare them directly. This is simple but
   unnecessarily exposes usable secrets in files and process configuration.
2. Accept keys from headers or query parameters. Query credentials leak more
   readily through URLs, browser history, access logs, and referrers.
3. Store SHA-256 digests and accept exactly one dedicated header. This supports
   an offline, restart-based configuration while reducing secret exposure.
4. Implement JWT/OIDC now. This provides richer identity but requires issuer,
   audience, algorithm, key-discovery, rotation, and clock-skew decisions that
   are outside this milestone.

## Decision

- Protected routes accept exactly one `X-API-Key` header value. Query
  parameters and duplicate header values are rejected.
- Credentials are 32–128 characters from the base64url-safe alphabet
  (`A-Z`, `a-z`, `0-9`, `-`, `_`). The bundled generator creates 32 random
  bytes and encodes them without padding.
- Configuration contains only lowercase or uppercase hexadecimal SHA-256
  digests. Plaintext credentials are generated once and must be kept in a
  secret manager or equivalent external secret store.
- Digest matching uses constant-time comparisons across the complete static
  registry. The registry is immutable after startup and safe for concurrent
  reads.
- A protected route declares `mode: api_key`. Every `required_scopes` entry
  must be present on the matched key. A public route cannot declare required
  scopes, and every route must declare its mode explicitly.
- Authentication and authorization run after the single deterministic route
  match and before proxying. A protected child route cannot fall through to a
  public parent route.
- Failures return generic JSON `401` or `403` responses. Credential values,
  digests, and client identifiers are not logged or returned.
- `X-API-Key` and every client-supplied `X-Aegis-*` header are removed before
  proxying. v0.3 does not send an identity assertion to upstreams.
- Key changes are loaded only at process startup. Rotation and revocation
  require replacing configuration and restarting the gateway.
- TLS is required between untrusted clients and AegisGate outside local
  development. The gateway does not make bearer keys safe over plaintext HTTP.

## Consequences

This design is small, auditable, and has no request-path network dependency.
It provides application-level access control but not end-user identity,
session management, fine-grained resource ownership, automated expiry, or
instant revocation. Static digest configuration becomes operationally awkward
at larger scale, so a later control plane or standards-based identity system
will need a separate trust-model decision.

API keys alone are insufficient for high-value user data unless combined with
TLS, secure secret distribution, rotation, monitoring, and appropriate
end-user authorization at the upstream service.
