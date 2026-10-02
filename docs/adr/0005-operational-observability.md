# ADR 0005: Operational observability with bounded telemetry

- Status: Accepted for v0.7 feature branch
- Date: 2026-10-02

## Context

The v0.6 gateway makes security decisions synchronously and delivers security
events asynchronously. Operators need to distinguish gateway failures,
upstream failures, intentional policy denials, and event loss without exposing
request secrets or making the collector part of the HTTP availability path.

## Options considered

1. Prometheus pull metrics with a private registry; OTel traces via OTLP HTTP.
2. Push both metrics and traces via OpenTelemetry.
3. Add synchronous export or per-request export goroutines.
4. Publish metrics on the public gateway listener.
5. Instrument the proxy via a generic HTTP wrapper that matches routes again.

## Decision

Use native Prometheus counters, gauges, histograms, and a read-only collector
over the existing v0.6 pipeline snapshot. Do not duplicate these metrics via
OTel. A private registry explicitly contains project, Go, and process metrics.
The metrics endpoint has a dedicated listener, exact configured path, explicit
timeouts, and no public Compose port. Listener bind or unexpected termination
fails the process; exporter runtime errors do not affect HTTP or readiness.

Use the official OTel SDK with parent-based ratio sampling, bounded batch
queue, OTLP HTTP export, and W3C Trace Context only. A single server span
encloses each request; rate-limit and WAF checks are internal spans and one
upstream client span is created in the transport. The transport injects only
traceparent/tracestate, deleting baggage. Route-pattern span names avoid raw
paths. Disabled tracing has no exporter or background worker.

The proxy always removes client-supplied trace headers during rewriting,
including when tracing is disabled. With tracing enabled, the transport then
injects the active span identity but discards client-controlled tracestate;
it never forwards baggage. Docker build
metadata is bounded and supplied as static build arguments, not derived from
runtime requests.

Request metrics use the one existing route match. Route IDs are validated
configuration values; methods, status classes, outcomes, decisions, modes,
actions, and transport results are finite enums. No request/trace IDs, URLs,
query strings, API identities, client addresses, WAF evidence, arbitrary
headers, or raw errors enter labels. Build metadata is static per process.
Traces include only bounded operational attributes; log correlation adds
trace_id and span_id to the single completion log. Existing v0.6 log fields
remain for compatibility and should be reviewed under deployment log policy.

During shutdown, drain gateway HTTP, then telemetry HTTP, then the security
event pipeline, then flush/shut down the trace provider within its deadline.
Policy denials are recorded as decisions, not span errors or 5xx availability
failures. Fail-closed dependency failures and upstream failures are errors.

## Consequences

Metrics and traces are process-local until scraped/exported. A sampling ratio
below one produces incomplete traces; security-event counters remain complete
within the process lifetime but cannot recover records lost on crash. The
demo Collector and Jaeger have no durable trace storage. Operators must
protect and restrict the dedicated metrics listener in non-demo deployments.
Prometheus latency histograms have buckets from 1 ms through 10 s, suitable
for a gateway but not high-resolution sub-millisecond analysis. Queue
utilization example rules assume the Compose capacity and need adjustment
when capacities change. The design avoids a second route match and avoids
making telemetry dependencies part of request authorization.
