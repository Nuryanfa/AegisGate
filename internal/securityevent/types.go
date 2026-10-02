package securityevent

import (
	"strings"
	"time"
	"unicode/utf8"
)

const (
	EventSchemaV1 = "aegis.security_event.v1"
	AlertSchemaV1 = "aegis.security_alert.v1"
	EventTypeWAF  = "waf_request_inspection"
	DetectorRule  = "AG-D2001"
	DetectorBlock = "AG-D2002"

	maxRequestIDBytes = 128
	maxRouteIDBytes   = 64
	maxModeBytes      = 16
	maxActionBytes    = 16
	maxReasonBytes    = 64
	maxMethodBytes    = 32
	maxPathClassBytes = 32
	maxSeverityBytes  = 16
	maxRuleIDBytes    = 32
	maxMatchedRules   = 32
)

type EventInput struct {
	OccurredAt         time.Time
	RequestID          string
	RouteID            string
	WAFMode            string
	Action             string
	ReasonClass        string
	AnomalyScore       int
	MatchedRuleIDs     []string
	HighestSeverity    string
	Method             string
	PathClassification string
	InspectionDuration time.Duration
}

// Event has no exported mutable fields. NewEvent bounds every value and copies
// the matched-rule slice before it can enter the asynchronous pipeline.
type Event struct {
	schemaVersion      string
	eventType          string
	occurredAt         time.Time
	requestID          string
	routeID            string
	wafMode            string
	action             string
	reasonClass        string
	anomalyScore       int
	matchedRuleIDs     []string
	highestSeverity    string
	method             string
	pathClassification string
	inspectionDuration time.Duration
}

func NewEvent(input EventInput) Event {
	rules := make([]string, 0, min(len(input.MatchedRuleIDs), maxMatchedRules))
	seen := make(map[string]struct{}, min(len(input.MatchedRuleIDs), maxMatchedRules))
	for _, id := range input.MatchedRuleIDs {
		id = boundText(id, maxRuleIDBytes)
		if id == "" || !strings.HasPrefix(id, "AG-") {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		rules = append(rules, id)
		if len(rules) == maxMatchedRules {
			break
		}
	}
	occurred := input.OccurredAt.UTC()
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	score := input.AnomalyScore
	if score < 0 {
		score = 0
	}
	duration := input.InspectionDuration
	if duration < 0 {
		duration = 0
	}
	return Event{
		schemaVersion: EventSchemaV1, eventType: EventTypeWAF, occurredAt: occurred,
		requestID: boundText(input.RequestID, maxRequestIDBytes), routeID: boundText(input.RouteID, maxRouteIDBytes),
		wafMode: boundText(input.WAFMode, maxModeBytes), action: boundText(input.Action, maxActionBytes),
		reasonClass: boundText(input.ReasonClass, maxReasonBytes), anomalyScore: score, matchedRuleIDs: rules,
		highestSeverity: boundText(input.HighestSeverity, maxSeverityBytes), method: boundText(input.Method, maxMethodBytes),
		pathClassification: boundText(input.PathClassification, maxPathClassBytes), inspectionDuration: duration,
	}
}

func (e Event) SchemaVersion() string             { return e.schemaVersion }
func (e Event) EventType() string                 { return e.eventType }
func (e Event) OccurredAt() time.Time             { return e.occurredAt }
func (e Event) RequestID() string                 { return e.requestID }
func (e Event) RouteID() string                   { return e.routeID }
func (e Event) WAFMode() string                   { return e.wafMode }
func (e Event) Action() string                    { return e.action }
func (e Event) ReasonClass() string               { return e.reasonClass }
func (e Event) AnomalyScore() int                 { return e.anomalyScore }
func (e Event) HighestSeverity() string           { return e.highestSeverity }
func (e Event) Method() string                    { return e.method }
func (e Event) PathClassification() string        { return e.pathClassification }
func (e Event) InspectionDuration() time.Duration { return e.inspectionDuration }
func (e Event) MatchedRuleIDs() []string          { return append([]string(nil), e.matchedRuleIDs...) }

type Alert struct {
	schemaVersion string
	detectorID    string
	generatedAt   time.Time
	routeID       string
	ruleID        string
	count         int
	window        time.Duration
	severity      string
	reasonClass   string
}

func (a Alert) SchemaVersion() string  { return a.schemaVersion }
func (a Alert) DetectorID() string     { return a.detectorID }
func (a Alert) GeneratedAt() time.Time { return a.generatedAt }
func (a Alert) RouteID() string        { return a.routeID }
func (a Alert) RuleID() string         { return a.ruleID }
func (a Alert) Count() int             { return a.count }
func (a Alert) Window() time.Duration  { return a.window }
func (a Alert) Severity() string       { return a.severity }
func (a Alert) ReasonClass() string    { return a.reasonClass }

type RecordKind string

const (
	RecordEvent RecordKind = "security_event"
	RecordAlert RecordKind = "security_alert"
)

type Record struct {
	kind  RecordKind
	event Event
	alert Alert
}

func eventRecord(event Event) Record  { return Record{kind: RecordEvent, event: event} }
func alertRecord(alert Alert) Record  { return Record{kind: RecordAlert, alert: alert} }
func (r Record) Kind() RecordKind     { return r.kind }
func (r Record) Event() (Event, bool) { return r.event, r.kind == RecordEvent }
func (r Record) Alert() (Alert, bool) { return r.alert, r.kind == RecordAlert }

func boundText(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
