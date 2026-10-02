package securityevent

import (
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time              { return c.now }
func (c *fakeClock) Advance(value time.Duration) { c.now = c.now.Add(value) }

func TestDetectorThresholdIsolationAndMultipleRules(t *testing.T) {
	clock := &fakeClock{now: time.Unix(100, 0)}
	d := newDetector(DetectionOptions{Enabled: true, Window: time.Minute, RuleMatchThreshold: 2, BlockThreshold: 2, Cooldown: 10 * time.Second, MaxKeys: 20}, clock)
	event := detectorEvent("users", "audit", "AG-1001", "AG-1002")
	if alerts := d.process(event); len(alerts) != 0 {
		t.Fatalf("below threshold alerts = %v", alerts)
	}
	alerts := d.process(event)
	if len(alerts) != 2 || alerts[0].DetectorID() != DetectorRule || alerts[0].Count() != 2 || alerts[1].RuleID() != "AG-1002" {
		t.Fatalf("threshold alerts = %#v", alerts)
	}
	if alerts := d.process(detectorEvent("orders", "audit", "AG-1001")); len(alerts) != 0 {
		t.Fatalf("route state was not isolated: %#v", alerts)
	}
	if alerts := d.process(detectorEvent("users", "audit", "AG-1003")); len(alerts) != 0 {
		t.Fatalf("rule state was not isolated: %#v", alerts)
	}
}

func TestDetectorAlertsOncePerWindowEvenAfterCooldown(t *testing.T) {
	clock := &fakeClock{now: time.Unix(400, 0)}
	d := newDetector(DetectionOptions{Enabled: true, Window: time.Minute, RuleMatchThreshold: 2,
		BlockThreshold: 2, Cooldown: 5 * time.Second, MaxKeys: 10}, clock)
	event := detectorEvent("users", "block", "AG-1001")
	if alerts := d.process(event); len(alerts) != 0 {
		t.Fatalf("below-threshold alerts = %#v", alerts)
	}
	if alerts := d.process(event); len(alerts) != 2 {
		t.Fatalf("threshold alerts = %#v", alerts)
	}
	clock.Advance(6 * time.Second)
	for range 3 {
		if alerts := d.process(event); len(alerts) != 0 {
			t.Fatalf("repeated alert in one fixed window = %#v", alerts)
		}
	}
	clock.Advance(time.Minute)
	if alerts := d.process(event); len(alerts) != 0 {
		t.Fatalf("first event in new window alerted = %#v", alerts)
	}
	if alerts := d.process(event); len(alerts) != 2 || alerts[0].Count() != 2 || alerts[1].Count() != 2 {
		t.Fatalf("new-window threshold alerts = %#v", alerts)
	}
}

func TestDetectorDoesNotAlertAfterThresholdCrossingDuringCooldown(t *testing.T) {
	clock := &fakeClock{now: time.Unix(500, 0)}
	d := newDetector(DetectionOptions{Enabled: true, Window: 10 * time.Second, RuleMatchThreshold: 2,
		BlockThreshold: 2, Cooldown: 15 * time.Second, MaxKeys: 10}, clock)
	event := detectorEvent("users", "audit", "AG-1001")
	d.process(event)
	if alerts := d.process(event); len(alerts) != 1 {
		t.Fatalf("initial alert = %#v", alerts)
	}
	clock.Advance(11 * time.Second)
	d.process(event)
	if alerts := d.process(event); len(alerts) != 0 {
		t.Fatalf("cooldown did not suppress crossing: %#v", alerts)
	}
	clock.Advance(5 * time.Second)
	if alerts := d.process(event); len(alerts) != 0 {
		t.Fatalf("alerted after threshold was already crossed: %#v", alerts)
	}
}

func TestDetectorBlockWindowCooldownAndCleanup(t *testing.T) {
	clock := &fakeClock{now: time.Unix(200, 0)}
	options := DetectionOptions{Enabled: true, Window: 5 * time.Second, RuleMatchThreshold: 2, BlockThreshold: 2, Cooldown: 10 * time.Second, MaxKeys: 10}
	d := newDetector(options, clock)
	blocked := detectorEvent("orders", "block")
	if len(d.process(blocked)) != 0 {
		t.Fatal("alert below block threshold")
	}
	alerts := d.process(blocked)
	if len(alerts) != 1 || alerts[0].DetectorID() != DetectorBlock || alerts[0].RuleID() != "" {
		t.Fatalf("block alerts = %#v", alerts)
	}
	if len(d.process(blocked)) != 0 {
		t.Fatal("cooldown did not suppress alert")
	}
	clock.Advance(6 * time.Second)
	if len(d.process(blocked)) != 0 {
		t.Fatal("new window emitted before threshold")
	}
	if len(d.process(blocked)) != 0 {
		t.Fatal("cooldown did not span windows")
	}
	clock.Advance(5 * time.Second)
	if len(d.process(blocked)) != 0 {
		t.Fatal("fresh window emitted before threshold")
	}
	alerts = d.process(blocked)
	if len(alerts) != 1 {
		t.Fatalf("no alert after cooldown and threshold: %#v", alerts)
	}
	clock.Advance(11 * time.Second)
	d.cleanup(clock.Now())
	if d.activeKeys() != 0 {
		t.Fatalf("expired detector keys = %d", d.activeKeys())
	}
}

func TestDetectorMaximumKeyPolicyDropsNewKeys(t *testing.T) {
	clock := &fakeClock{now: time.Unix(300, 0)}
	d := newDetector(DetectionOptions{Enabled: true, Window: time.Minute, RuleMatchThreshold: 2, BlockThreshold: 2, Cooldown: time.Minute, MaxKeys: 1}, clock)
	d.process(detectorEvent("users", "audit", "AG-1001"))
	d.process(detectorEvent("orders", "audit", "AG-1002"))
	if d.activeKeys() != 1 || d.keyDrops != 1 {
		t.Fatalf("active=%d drops=%d", d.activeKeys(), d.keyDrops)
	}
	if alerts := d.process(detectorEvent("users", "audit", "AG-1001")); len(alerts) != 1 {
		t.Fatalf("existing key stopped progressing: %#v", alerts)
	}
}

func detectorEvent(route, action string, rules ...string) Event {
	return NewEvent(EventInput{OccurredAt: time.Unix(1, 0), RequestID: "req", RouteID: route, WAFMode: "audit",
		Action: action, ReasonClass: "rule_match", MatchedRuleIDs: rules, Method: "GET"})
}
