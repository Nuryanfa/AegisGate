package securityevent

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewEventSchemaBoundsAndDefensiveCopy(t *testing.T) {
	rules := []string{"AG-1001", "AG-1002", "AG-1001", "invalid"}
	event := NewEvent(EventInput{
		OccurredAt: time.Date(2026, 10, 2, 1, 2, 3, 0, time.FixedZone("test", 7*60*60)),
		RequestID:  strings.Repeat("é", 100), RouteID: strings.Repeat("r", 100), WAFMode: "audit",
		Action: "audit", ReasonClass: "rule_match", AnomalyScore: -1, MatchedRuleIDs: rules,
		HighestSeverity: "high", Method: "GET", PathClassification: "route_descendant", InspectionDuration: -1,
	})
	rules[0] = "AG-MUTATED"
	if event.SchemaVersion() != EventSchemaV1 || event.EventType() != EventTypeWAF || event.OccurredAt().Location() != time.UTC {
		t.Fatalf("unexpected schema/time: %q %q %v", event.SchemaVersion(), event.EventType(), event.OccurredAt())
	}
	if len(event.RequestID()) > maxRequestIDBytes || !utf8.ValidString(event.RequestID()) || len(event.RouteID()) > maxRouteIDBytes {
		t.Fatalf("unbounded event fields: request=%q route=%q", event.RequestID(), event.RouteID())
	}
	if event.AnomalyScore() != 0 || event.InspectionDuration() != 0 {
		t.Fatalf("negative values were retained: %#v", event)
	}
	got := event.MatchedRuleIDs()
	if len(got) != 2 || got[0] != "AG-1001" || got[1] != "AG-1002" {
		t.Fatalf("rules = %v", got)
	}
	got[0] = "AG-CHANGED"
	if event.MatchedRuleIDs()[0] != "AG-1001" {
		t.Fatal("matched-rule getter exposed mutable state")
	}
}

func TestSlogSinkUsesPrivacyAllowlist(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	sink, err := NewSlogSink(logger)
	if err != nil {
		t.Fatal(err)
	}
	event := NewEvent(EventInput{OccurredAt: time.Unix(1, 0), RequestID: "req-1", RouteID: "users", WAFMode: "audit",
		Action: "audit", ReasonClass: "rule_match", MatchedRuleIDs: []string{"AG-1001"}, Method: "POST"})
	if err := sink.Write(context.Background(), eventRecord(event)); err != nil {
		t.Fatal(err)
	}
	logged := output.String()
	for _, forbidden := range []string{"api-key-secret", "authorization-secret", "cookie-secret", "query-secret", "body-secret", "peer-ip", "client-id", "raw-evidence"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("sink leaked forbidden value %q: %s", forbidden, logged)
		}
	}
	for _, required := range []string{EventSchemaV1, "AG-1001", "req-1", "users"} {
		if !strings.Contains(logged, required) {
			t.Fatalf("sink omitted allowlisted field %q: %s", required, logged)
		}
	}
}

func TestOptionsValidation(t *testing.T) {
	valid := DefaultOptions()
	if err := valid.Validate(); err != nil {
		t.Fatalf("default options invalid: %v", err)
	}
	tests := []Options{
		{},
		func() Options { o := valid; o.QueueCapacity = MaxQueueCapacity + 1; return o }(),
		func() Options { o := valid; o.Workers = 0; return o }(),
		func() Options { o := valid; o.SinkTimeout = MaxSinkTimeout + time.Second; return o }(),
		func() Options { o := valid; o.Detection.RuleMatchThreshold = 0; return o }(),
		func() Options { o := valid; o.Detection.MaxKeys = MaxDetectionKeys + 1; return o }(),
		func() Options { o := valid; o.Detection = DetectionOptions{Window: time.Second}; return o }(),
	}
	for index, options := range tests {
		if err := options.Validate(); err == nil {
			t.Errorf("case %d: Validate() error = nil", index)
		}
	}
}
