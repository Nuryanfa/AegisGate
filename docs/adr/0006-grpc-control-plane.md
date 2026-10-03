# ADR 0006: Single-authority gRPC configuration distribution

Status: accepted for v0.8 feature branch (2026-10-03)

## Context

The v0.7 gateway loads routes and API-client digests at startup. A portfolio-scale distributed deployment needs one explicit authority that can update multiple gateways without mutating their request-path policy maps. Node-local Redis credentials, TLS keys, listeners, telemetry, and pipeline capacity must stay local.

## Options

1. Poll a shared YAML file: easy, but no reliable acknowledgements, ordering, or bounded fan-out.
2. Build an administrative database and bus: operationally much larger than this milestone.
3. Use a versioned typed gRPC bidirectional stream with in-memory single authority and local bootstrap.

## Decision

Choose option 3. The control plane validates strict YAML, converts to typed protobuf, computes a canonical SHA-256 content revision, and publishes only changed content. Each stream has its own monotonically increasing sequence. Gateways validate and compile a complete immutable runtime and publish it with one atomic pointer store; ACK follows publication. An unchanged revision is ACKed without compilation. Failed validation or local dependency checks retain the previous runtime and produce a bounded NACK.

The authority has a fixed maximum client count and one pending latest-snapshot slot per client. There is no persistent history or consensus. Gateway streams use one reconnect supervisor with exponential backoff and bounded jitter. Production requires mTLS on both sides; plaintext is allowed only in explicitly configured development mode. Gateway bootstrap and staleness behavior are explicit policies. Freshness is based on the last valid authenticated snapshot or heartbeat, not the age of the last configuration change. The authority sends heartbeats every 30 seconds; `stale_after` is at least one minute. Last accepted snapshot time remains a separate metric. The gRPC transport uses explicit OpenTelemetry tracer providers and W3C TraceContext propagation when enabled.

## Consequences

- In-flight requests retain their loaded handler; new requests use the new handler.
- A control-plane outage cannot destroy the last-known-good runtime. `stale_policy: deny` eventually returns JSON `503 CONFIG_STALE`; `serve` keeps serving.
- Control-plane loss, its restart, and stream-local sequence reset are independent of content identity.
- A control-plane restart can still lose an unpersisted update; the source YAML must be managed and backed up externally.
- This is one writable authority, not HA. There is no historical rollback, administration API, or secret distribution.
- Dynamic route IDs can otherwise accumulate metric series, so only 64 distinct IDs are admitted per process; later IDs map to `_other`.
