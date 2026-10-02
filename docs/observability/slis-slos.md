# Illustrative service indicators and objectives

These are example definitions and targets, not measured production reliability
claims. Choose targets only after observing real traffic and business impact.

| Signal | Indicator | Illustrative target |
| --- | --- | --- |
| Gateway availability | 1 - gateway `5xx` / all completed requests, from `aegisgate_http_requests_total` | 99.9% over 30 days |
| Upstream reliability | 1 - upstream `error`/`timeout` / all upstream attempts | 99.5% over 30 days |
| Gateway latency | p95 of request-duration histogram, segmented by route | <250 ms over 30 days, subject to upstream behavior |
| Security-event retention | 1 - ingress/delivery drops / accepted + ingress drops | 99.99% over 30 days |
| Telemetry availability | Successful Prometheus scrapes and Collector export health | Observe separately; never gate HTTP readiness on export |

HTTP `401`, `403`, and `429` are intentional policy outcomes and not gateway
availability failures. WAF blocks also remain policy outcomes. An internal
dependency fail-closed response (`503`) is an availability failure, whereas
an upstream-origin `5xx` is shown separately via upstream result metrics.
Gateway `5xx` includes upstream failures in the user-facing numerator; use
both indicators to assign cause, not to count them as two incidents.

Security-event counters are process-local and reset on restart. The loss
indicator cannot detect unreported loss after an abrupt crash. Trace sampling
and exporter drops mean traces are diagnostic samples, not an audit trail.
