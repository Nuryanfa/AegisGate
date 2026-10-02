package securityevent

import (
	"context"
	"errors"
	"log/slog"
)

type Sink interface {
	Write(context.Context, Record) error
}

type SlogSink struct{ logger *slog.Logger }

func NewSlogSink(logger *slog.Logger) (*SlogSink, error) {
	if logger == nil {
		return nil, errors.New("security-event slog sink requires a logger")
	}
	return &SlogSink{logger: logger}, nil
}

func (s *SlogSink) Write(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch record.kind {
	case RecordEvent:
		e := record.event
		s.logger.LogAttrs(ctx, slog.LevelWarn, "asynchronous WAF security event",
			slog.String("schema_version", e.schemaVersion), slog.String("event_type", e.eventType),
			slog.Time("occurred_at", e.occurredAt), slog.String("request_id", e.requestID),
			slog.String("route_id", e.routeID), slog.String("waf_mode", e.wafMode),
			slog.String("action", e.action), slog.String("reason", e.reasonClass),
			slog.Int("anomaly_score", e.anomalyScore), slog.Any("matched_rule_ids", append([]string(nil), e.matchedRuleIDs...)),
			slog.String("highest_severity", e.highestSeverity), slog.String("method", e.method),
			slog.String("path_class", e.pathClassification), slog.Duration("inspection_duration", e.inspectionDuration))
	case RecordAlert:
		a := record.alert
		s.logger.LogAttrs(ctx, slog.LevelWarn, "asynchronous security alert",
			slog.String("schema_version", a.schemaVersion), slog.String("detector_id", a.detectorID),
			slog.Time("generated_at", a.generatedAt), slog.String("route_id", a.routeID),
			slog.String("rule_id", a.ruleID), slog.Int("count", a.count),
			slog.Duration("window", a.window), slog.String("severity", a.severity),
			slog.String("reason", a.reasonClass))
	default:
		return errors.New("unknown security-event record kind")
	}
	return nil
}
