# Operating AegisGate observability

The `observability` YAML block is optional. With no block, both metrics and
tracing are off and v0.6 files remain valid. When present, set
`service_name`, `environment`, and at least one enabled subsection. Enabled
subsections require all shown fields in `configs/config.example.yaml`; unused
settings on disabled subsections and unknown YAML fields are rejected. The
block is file-only; existing server environment overrides do not change it.
All durations are positive and at most 30s. Tracing uses a ratio in [0,1], a
queue of 1..65536, and a batch of 1..4096 no larger than the queue. The OTLP
endpoint is an HTTP(S) origin; the exporter appends `/v1/traces`. Credentials,
headers, and tokens are not accepted in YAML.

Local non-container example binds `127.0.0.1:9090`; query
`http://127.0.0.1:9090/metrics`. This listener has no gateway middleware or
authentication. Never expose it on a public interface. In Compose it binds
inside the container network only and has no host port mapping. `/healthz`
and `/readyz` remain on the public listener. Telemetry bind failure or
unexpected termination is fatal; OTLP export failure is not. A missing
Collector may cause exporter diagnostics but will not change HTTP decisions
or readiness.

## Local demo

```bash
docker compose --profile observability up --build
```

Send traffic to `http://localhost:8080/api/users/42`. Prometheus is at
`http://127.0.0.1:9091`, Jaeger at `http://127.0.0.1:16686`, and Grafana at
`http://127.0.0.1:3000`. The dashboard is provisioned under **AegisGate**.
Prometheus scrapes `gateway:9090/metrics` inside Compose. The demonstration
uses Grafana anonymous Viewer and ephemeral telemetry storage; it is not a
production deployment. Without the profile, the gateway still runs, though
the Docker example's enabled tracer cannot reach its Collector; use a local
override config with tracing disabled to avoid export warnings.
If 8080 is occupied, set `AEGIS_GATEWAY_PORT=18080` and use that host port.
Compose passes optional `AEGIS_BUILD_VERSION`, `AEGIS_BUILD_COMMIT`, and
`AEGIS_BUILD_TIME` to the gateway build; each is checked as a bounded,
non-secret static value (1–64 safe ASCII characters). See the Docker build
example in the README. The default image reports `dev`/`unknown`/`unknown`.

For a protected-route demo, replace the placeholder digest in a gitignored
`configs/local.yaml`, provide its path via `AEGIS_CONFIG_FILE`, and keep the
plaintext key outside the repository. A rejected request can be generated
without a key at `/api/orders/42`; it should count as `unauthorized`, not a
gateway availability failure. A WAF audit on `/api/users` can be generated
with a known test signature in the query. Do not log, screenshot, or share
secret-bearing query strings from real traffic.

## Metric catalog and labels

All project metrics use `aegisgate_`; Go/process runtime metrics are explicit
standard collectors. Histograms use buckets 1, 2.5, 5, 10, 25, 50, 100, 250,
500 ms and 1, 2.5, 5, 10 s.

| Family | Meaning | Labels |
| --- | --- | --- |
| `aegisgate_build_info` | Static build value 1 | version, commit, build_time |
| `aegisgate_http_requests_total` | Completed requests | route_id, method, status_class, outcome |
| `aegisgate_http_request_duration_seconds` | Completion latency | route_id, method, outcome |
| `aegisgate_http_requests_in_flight` | Active requests | none |
| `aegisgate_upstream_requests_total` | Upstream transport/result | route_id, result |
| `aegisgate_upstream_request_duration_seconds` | Upstream time to headers/error | route_id, result |
| `aegisgate_auth_decisions_total` | Public/authentication/authorization | route_id, decision |
| `aegisgate_rate_limit_decisions_total` | Redis policy outcomes | route_id, decision |
| `aegisgate_rate_limit_check_duration_seconds` | Rate check latency | route_id |
| `aegisgate_waf_decisions_total` | WAF inspection outcomes | route_id, mode, action |
| `aegisgate_waf_inspection_duration_seconds` | WAF inspection time | route_id |
| `aegisgate_security_events_total`, `aegisgate_security_event_processed_total`, `aegisgate_security_event_alerts_total`, `aegisgate_security_event_delivery_total` | Pipeline snapshot counters | none |
| `aegisgate_security_event_ingress_drops_total`, `aegisgate_security_event_delivery_drops_total`, `aegisgate_security_event_sink_errors_total`, `aegisgate_security_event_detection_key_drops_total` | Pipeline loss/error counters | none |
| `aegisgate_security_event_ingress_queue_depth`, `aegisgate_security_event_delivery_queue_depth`, `aegisgate_security_event_active_detection_keys` | Pipeline gauges | none |

`route_id` comes only from startup-validated route configuration; unknown
routes use `_none`. HTTP methods are normalized to seven common verbs or
`OTHER`; statuses are classes; outcomes and decisions use fixed enums. Never
add raw path, query, upstream URL, hostname, IP, API/client identity, request
ID, trace ID, user agent, error string, or header value to a metric label.
Large route tables multiply series; review route count and label budgets before
deployment. Build-info labels change only when the process is rebuilt.

## Traces, privacy, and shutdown

The server span is named for a configured route pattern, with `gateway.request`
for unmatched paths. Rate-limit and WAF spans are internal; upstream requests
produce one client span and receive W3C trace context. Client-supplied
`traceparent`, `tracestate`, and `baggage` are stripped from the proxy request
even when tracing is disabled. When enabled, the gateway injects the current
span's trace identity after stripping, without relaying client-controlled
tracestate entries. Invalid inbound context is ignored; arbitrary baggage is
removed. Only bounded route/policy/status
attributes and configured upstream hostname are recorded. A sampled request's
completion log adds `trace_id` and `span_id`; no trace ID is a metric label.
The existing completion log still includes path and direct peer address from
v0.6, so apply an appropriate access-log retention/redaction policy. No new
body, credential, client ID, evidence, or full trace header is logged.

Gateway HTTP drains first, then the telemetry listener, then the security
event pipeline, then the trace provider flushes within configured deadlines.
A timeout can drop buffered spans. Collector outages and sampling also mean
Jaeger is never an authoritative record of all requests. See
[`SLIs and SLOs`](observability/slis-slos.md) and
[`ADR 0005`](adr/0005-operational-observability.md).
