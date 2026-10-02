# ADR 0004: Bounded asynchronous security-event pipeline

- Status: Accepted
- Date: 2026-10-02

## Context

v0.5 wrote WAF security records synchronously from the request handler. That
made sink latency part of request latency and coupled policy enforcement to an
operational side effect. v0.6 needs observable WAF events and small burst
detection without retaining requests, creating unbounded work, or pretending
that an in-memory component is durable.

WAF parsing, normalization, scoring, audit/enforce selection, and HTTP rejection
must remain synchronous because they determine whether a request may reach an
upstream. Event transport and correlation do not determine that decision.

## Options considered

1. Call the structured sink synchronously from the request path.
2. Start one goroutine for every event.
3. Append to an unbounded channel, slice, or map.
4. Block publishers until queue capacity is available.
5. Retry sink failures without a strict bound.
6. Log raw requests or evidence for later processing.
7. Add Kafka, a webhook, or an external SIEM dependency now.
8. Use bounded in-memory stages with non-blocking publication.

Options 1–7 were rejected. They respectively couple request latency to the
sink, allow unbounded goroutine growth, allow unbounded memory growth, propagate
backpressure into clients, create retry storms, violate the privacy boundary,
or add an operational system that this milestone cannot honestly operate or
guarantee.

## Decision

Use this process-local pipeline:

```text
HTTP/WAF path -> bounded ingress -> one detector -> bounded delivery -> fixed workers -> slog
                  drop newest                         bounded write timeout
```

### Publication and channel ownership

The proxy creates an immutable `aegis.security_event.v1` value containing only
bounded approved metadata. `Publish` holds a lifecycle read lock only around a
non-blocking channel select. It accepts immediately or drops the newest event.
Shutdown takes the write lock, marks the pipeline closed, and closes ingress;
therefore no publisher can race a send against channel close.

The pipeline owns both channels. Shutdown closes ingress exactly once. The
single detector goroutine is the only code that closes delivery, after ingress
has drained or cancellation forces abandonment. Workers only receive from
delivery and never close channels.

Production defaults are ingress 1,024, delivery 1,024, and two workers. Each
queue is capped at 65,536 and workers at 64. Delivery saturation blocks only the
detector stage. Backpressure then fills ingress, where HTTP-facing publication
remains non-blocking and drops new events. Drops are counted, not synchronously
logged per event.

### Detection

One detector goroutine exclusively owns two maps, so detector state requires
no mutex:

- `AG-D2001` uses `(route ID, stable WAF rule ID)` keys and evaluates every
  matched rule separately.
- `AG-D2002` uses route ID keys for WAF actions classified as `block`.

Both detectors use fixed windows, exact threshold crossings, server-generated
time, and cooldown suppression. State is capped by one shared `max_keys` value.
When full, expired state is removed first; if capacity is still unavailable,
the new key is discarded while existing keys continue. That deterministic
drop-new-key policy is counted. Detection is process-local, resets on restart,
and does not correlate gateway replicas.

### Delivery and failure behavior

A fixed worker pool calls a narrow `Sink.Write(context.Context, Record)`
interface. Every call has a bounded timeout, capped at ten seconds. The initial
sink explicitly allowlists fields into `log/slog`; it supports raw event and
`aegis.security_alert.v1` records. A failure increments `sink_errors_total`,
emits only a logarithmically rate-limited safe diagnostic, and the worker
continues. v0.6 performs no delivery retry.

The guarantee is best-effort, in-memory, non-durable delivery. A process crash,
queue saturation, shutdown deadline, or sink failure can lose records. Event
delivery never changes an HTTP response or WAF decision. This component is not
an audit ledger, message broker, SIEM, or cross-instance detector.

### Privacy

Events and alerts never contain API keys, authorization or cookie values,
query strings, request bodies, arbitrary headers, raw evidence or WAF patterns,
authenticated client IDs, peer IP addresses, upstream or Redis credentials,
internal errors, or stack traces. No request, context, URL, header, or body
pointer enters the pipeline. Mutable matched-rule slices are copied and all
text fields are length-bounded. The sink logs an explicit field allowlist
rather than reflecting arbitrary objects.

### Statistics and shutdown

Atomics expose a race-safe internal snapshot of accepted, ingress-dropped,
processed, alert, sink-error, delivered, delivery-dropped, and detector-key-drop
totals plus queue depths and active keys. Periodic and final summaries are
bounded structured logs. Prometheus is deferred to v0.7.

Shutdown ordering is:

1. The HTTP server stops accepting and drains active requests.
2. Pipeline publication closes under the lifecycle lock.
3. Ingress drains through the detector, which then closes delivery.
4. Workers drain delivery and exit.
5. The pipeline emits final counters.

If the configured pipeline deadline expires, its root context cancels sink
contexts and remaining work is abandoned and counted where practical. Shutdown
is idempotent and cannot wait indefinitely for a compliant sink.

## Consequences

Request latency is independent of queue capacity and compliant sink latency,
and concurrency and memory have explicit limits. Operators must monitor drop
and sink-error counters and accept that event order across multiple workers is
not guaranteed. Detector results differ across replicas and disappear on
restart. Durable transport, cross-instance detection, external sinks, public
metrics, and delivery retries require later designs with new operational and
security decisions.
