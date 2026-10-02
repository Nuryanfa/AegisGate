# ADR 0003: Bounded request inspection and WAF foundation

Status: Accepted

Date: 2026-09-29

## Context

AegisGate v0.5 needs a small request-inspection control before proxying. The
control must recognize a limited set of suspicious inputs without turning
untrusted request size, field count, encoding, or regular-expression work into
an unbounded resource cost. It must also preserve the v0.3 authentication and
v0.4 distributed-rate-limit trust boundaries.

This feature is an educational security layer. Signature matching without an
application's syntax and authorization context has unavoidable false positives
and false negatives.

## Options considered

1. Forward all traffic and only log raw requests. This provides no enforcement
   and would expose credentials and payloads in logs.
2. Recursively decode and run user-configured regular expressions. This creates
   ambiguous semantics and attacker-controlled CPU and memory risk.
3. Add an external enterprise WAF. That would dominate the portfolio's data
   path and is outside this milestone.
4. Use a small immutable built-in rule set, one decoding pass, explicit media
   types, and validated per-route limits.

## Decision

### Pipeline and modes

One route is matched once. Authentication and scope authorization run first,
then Redis rate limiting, bounded WAF inspection, and the existing reverse
proxy. Gateway-owned health endpoints bypass route policies. Omitted `waf`
means disabled. Explicit `disabled` accepts no unused protective-looking
settings. `audit` records matches and forwards; `enforce` returns JSON `403`
when the anomaly score reaches the positive configured threshold.

An unexpected internal inspection error is fail-closed with JSON `503` in
enforce mode. Audit mode allows the request with a bounded warning so an audit
rollout does not become an availability dependency. Invalid client input and
resource limits are not signature matches: they retain their own `400`, `413`,
or `415` status in both audit and enforce modes.

### Canonical representation

- Method and Go's once-decoded `URL.Path` are always available to rules.
- Query strings are capped before `url.ParseQuery`. Percent encoding is decoded
  once, and `+` means space. Names and every duplicate value remain separate.
- Headers are byte-capped. Names and values are inspected separately as a
  canonical lowercase-name/value pair. Authorization, cookie, proxy
  authorization, API-key, and set-cookie values are never added to the rule
  representation.
- Text must be valid UTF-8 and contain no NUL. Malformed percent escapes and
  ambiguous text are rejected instead of guessed.
- Values from separate fields are not concatenated. This prevents synthetic
  cross-field matches but means application-level recombination can evade this
  version and must be handled by the upstream.
- Normalization never changes URL, query, header, or body bytes forwarded to an
  upstream. Body bytes are buffered once and restored exactly.
- JSON object keys and string scalar values are rule candidates. Form names and
  every form value are candidates; a plain-text body is one bounded candidate.
  JSON structure, numbers, booleans, and null are validated and counted but are
  not converted into synthetic text for signature matching.

### Body contract and limits

Body inspection supports `application/json`,
`application/x-www-form-urlencoded`, and `text/plain`, with absent or UTF-8
charset parameters. A non-empty inspected body with no content type,
multipart content, another media type, or non-identity content encoding is
rejected with `415`. A zero-length body needs no content type. Chunked input is
accepted but read through the same hard byte ceiling. Go's HTTP server rejects
many invalid Content-Length forms before the handler; an invalid length that
does reach the engine is rejected.

Method and path inspection have fixed ceilings of 32 bytes and 8 KiB. Query and
headers are each capped at 64 KiB by configuration. A buffered body is capped
at 2 MiB, JSON depth at 64, and JSON fields/elements at 10,000.
Individual route limits must be positive and within those maxima. The complete
body is read through `limit + 1`; AegisGate never forwards an uninspected tail.
JSON accepts exactly one syntactically valid value. There is no decompression,
multipart file scanning, disk buffering, response inspection, or recursive
decoding in v0.5.

### Rules, scoring, and concurrency

`core-v1` is an immutable startup-compiled set of six RE2 rules with stable IDs
`AG-1001` through `AG-1006`. They cover stronger representative combinations
for SQL injection, XSS, path traversal, command injection, selected residual
double-encoding signals, and a dangerous method-override header. Common single
characters and standalone words are not rules. Each rule contributes its fixed
score; the internal result contains total score, bounded matched IDs, highest
severity, and action.

At most 10,000 canonical values and six rules are evaluated. Patterns are not
accepted from YAML, are never compiled per request, create no goroutines, and
share no mutable state. A panic is recovered as an internal inspection failure.

### Events and privacy

One structured security event is emitted only for a match, block, parse or
normalization failure, limit breach, or internal failure. Fields are bounded to
request ID, route ID, mode, action, score, stable rule IDs, highest severity,
method, route-root/descendant classification, reason class, and duration.
Events omit API keys, authenticated client IDs, peer addresses, authorization
and cookie headers, query strings, bodies, header values, raw evidence,
patterns, Redis credentials, and internal errors.

## Consequences

The engine is predictable, independently testable, and cheap to disable. Audit
mode supports a safe rollout before enforcement:

```text
disabled -> audit -> review false positives -> tune threshold or route policy -> enforce
```

The rules can be bypassed and can still produce false positives. AegisGate is
not OWASP CRS, ModSecurity, an enterprise WAF, an IDS, malware scanner, or DDoS
mitigation service. Upstreams remain responsible for parameterized SQL,
contextual output encoding, allowlist validation, safe process execution,
filesystem authorization, authentication, and resource-level authorization.
