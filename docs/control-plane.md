# AegisGate v0.8 control plane

This feature branch adds a **single-authority**, in-memory gRPC control plane. It is not a highly available production control plane. The data plane still owns HTTP and telemetry listeners, Redis connectivity and credentials, security-event capacity, tracing exporter settings, and TLS private keys. Only routes, policy values, API-client IDs, SHA-256 digests, and scopes travel in protobuf snapshots. Plaintext API keys never travel over the stream.

## Protocol and atomic application

`api/controlplane/v1/configuration.proto` defines `ConfigurationService.Sync`, a bidirectional stream. A gateway registers an ASCII instance ID, protocol version 1, and current content revision. The server immediately sends its latest snapshot. The gateway checks stream-local sequence ordering, recalculates the canonical SHA-256 revision, validates all typed fields and local capabilities, compiles a complete immutable handler, atomically swaps its runtime pointer, then sends an ACK. Failed candidates retain the prior runtime and get a sanitized NACK (`validation`, `dependency`, or `protocol`). Full snapshots, digests, and internal error strings are never logged or placed in NACK messages.

Canonicalization sorts routes, API clients, and scope sets before deterministic protobuf marshaling. YAML field order, whitespace, and file mtime do not identify a configuration. Generation time and stream sequence are excluded. Sequence restarts at 1 on each new stream, so a reconnect can accept a new authority revision even when its number is lower than a prior stream's last number. The same revision is idempotently ACKed without rebuilding. A request loads the active runtime pointer once; requests already using an older runtime finish on it. No global configuration mutex sits in request dispatch.

The server admits at most `max_clients` TCP connections and Sync streams, including idle connections before stream registration. Each stream owns a single pending outbound snapshot slot; publication replaces an older pending snapshot and never waits for a slow client. gRPC message sizes, ACK queue capacity, reconnect delay, and timeouts are bounded. The gateway has one reconnect supervisor with exponential backoff and up to 25% jitter, and one stream sender goroutine that is joined before reconnect. Keepalive is configured on the server.

## Configuration and security

Start from [control-plane.example.yaml](../configs/control-plane.example.yaml), [snapshot example](../configs/snapshots/example.yaml), and [gateway demo config](../configs/config.control-plane-demo.yaml). The control plane reads `AEGIS_CONTROL_PLANE_CONFIG_PATH`; the gateway still reads `AEGIS_CONFIG_PATH`. Strict YAML rejects unknown fields and multiple documents. Local gateway environment overrides retain v0.7 precedence; `AEGIS_CONTROL_PLANE_INSTANCE_ID` overrides only the safe ASCII instance ID. The control plane refuses startup without a valid initial snapshot. `SIGHUP` reloads explicitly; an invalid candidate is rejected and the last-known-good snapshot and gRPC health `SERVING` remain. There is no file polling.

`control_plane` absent preserves v0.7 startup and creates no gRPC client. When present, local routes and API keys are the bootstrap snapshot. `require_remote` keeps proxied traffic at `503 CONFIG_NOT_READY` and readiness false until a remote revision is accepted. `use_bootstrap` serves local routes immediately. `initial_sync_timeout` logs a bounded warning; it does not kill the gateway during an outage. `stale_policy: serve` keeps the last known runtime; `deny` returns JSON `503 CONFIG_STALE` and readiness false after `stale_after` since the last valid snapshot or heartbeat on the configured stream (or gateway start before first contact). Contact is authenticated with mTLS; the insecure development demo provides no peer authentication. The authority sends heartbeats every 30s, so `stale_after` must be at least 1m. A connected but silent stream can become stale; an unchanged revision remains healthy while heartbeats arrive. Disconnection does not immediately mark configuration stale, and valid contact after reconnection clears staleness. Liveness is process-only. Route deadlines must be below the local server write timeout. Remote rate-limited routes require a locally configured limiter; WAF routes require the local inspector and security-event pipeline. The candidate is never partially applied.

Production gateway configuration rejects plaintext gRPC. Production control-plane configuration also requires mTLS. The control plane validates gateway certificates against its configured client CA; the gateway validates the server certificate, CA, and server name. TLS is at least 1.2. Certificates and keys are read from files at process start, not dynamically reloaded. Use a proper CA and protected secret mounts in deployment. The checked-in examples use **insecure development transport only**, placeholder digests, and no real private keys. No gRPC reflection is registered.

Gateway Prometheus metrics include `aegisgate_control_plane_connected`, `reconnects_total`, `snapshots_received_total`, `snapshot_apply_total{result,reason}`, `snapshot_apply_duration_seconds`, `last_success_timestamp_seconds`, `last_contact_timestamp_seconds`, and `stale`. Control-plane metrics include `clients`, `snapshots_published_total`, `acks_total`, `nacks_total`, and `reload_total{result}`. Route metrics admit at most 64 distinct route IDs per process; later IDs use `_other`. No revision, instance ID, key ID, path, URL, address, certificate subject, or error string is a metric label. Optional `tracing_endpoint` enables control-plane gRPC server and reload spans; a gateway with tracing enabled propagates W3C TraceContext over gRPC and emits transport, stream, validation, compilation, and publication spans without recording protobuf contents.

## Local demonstration

Run from the repository root with Docker Compose:

```sh
docker compose --profile control-plane-demo up --build control-plane gateway-cp-a gateway-cp-b users-upstream orders-upstream
curl http://127.0.0.1:8084/api/users
curl http://127.0.0.1:8085/api/users
```

Both gateways bootstrap from the same file and receive the same remote revision. Edit `configs/snapshots/example.yaml`, for example change the users upstream to `http://orders-upstream:8081`, then run:

```sh
docker compose kill -s HUP control-plane
docker compose logs --tail=30 control-plane gateway-cp-a gateway-cp-b
curl http://127.0.0.1:8084/api/users
curl http://127.0.0.1:8085/api/users
```

Expect one new published revision, two ACKs, and responses from the changed upstream; existing in-flight requests continue on the handler they loaded. Next make the snapshot invalid (for example a duplicate route ID) and send HUP again: expect a rejected reload and unchanged revision/routes on both gateways. Restore the file and reload. Stop the authority with `docker compose stop control-plane`; after one minute these demo gateways return `503 CONFIG_STALE` because the demo chooses `deny`. Restart with `docker compose start control-plane`; they reconnect and resume without gateway restarts. Keep edits to this tracked demo file out of commits unless intended.

For protobuf development, install Buf v1.59.0, `protoc-gen-go` v1.36.12, and `protoc-gen-go-grpc` v1.5.1, then run `buf lint`, `buf generate`, and `buf breaking --against '.git#branch=main'` once the baseline branch contains `buf.yaml`. Generated Go files are committed and never hand-edited.

Failure recovery: correct a bad source file and HUP again; restore the authority process after outage; if mTLS fails, verify CA trust, certificate validity, server name, and file mounts, then restart. Metrics and `/readyz` distinguish data-plane process health from configuration readiness. There is no persistent snapshot history or automatic rollback, and a restart loads the source file rather than recovering an uncommitted in-memory revision.
