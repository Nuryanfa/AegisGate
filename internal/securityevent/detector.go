package securityevent

import "time"

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type ruleKey struct{ routeID, ruleID string }
type windowState struct {
	windowStart time.Time
	count       int
	lastAlert   time.Time
}

type detector struct {
	options     DetectionOptions
	clock       Clock
	rules       map[ruleKey]windowState
	blocks      map[string]windowState
	nextCleanup time.Time
	keyDrops    uint64
}

func newDetector(options DetectionOptions, clock Clock) *detector {
	if clock == nil {
		clock = realClock{}
	}
	return &detector{options: options, clock: clock, rules: make(map[ruleKey]windowState), blocks: make(map[string]windowState)}
}

func (d *detector) process(event Event) []Alert {
	if !d.options.Enabled {
		return nil
	}
	now := d.clock.Now().UTC()
	if d.nextCleanup.IsZero() || !now.Before(d.nextCleanup) {
		d.cleanup(now)
		d.nextCleanup = now.Add(d.options.Window)
	}
	alerts := make([]Alert, 0, len(event.matchedRuleIDs)+1)
	for _, ruleID := range event.matchedRuleIDs {
		key := ruleKey{event.routeID, ruleID}
		state, ok := d.rules[key]
		if !ok {
			if !d.reserveKey(now) {
				continue
			}
			state = windowState{windowStart: now}
		}
		state, alert := d.update(state, now, d.options.RuleMatchThreshold, DetectorRule, event.routeID, ruleID, "medium", "repeated_waf_rule_activity")
		d.rules[key] = state
		if alert != nil {
			alerts = append(alerts, *alert)
		}
	}
	if event.action == "block" {
		state, ok := d.blocks[event.routeID]
		if ok || d.reserveKey(now) {
			if !ok {
				state = windowState{windowStart: now}
			}
			state, alert := d.update(state, now, d.options.BlockThreshold, DetectorBlock, event.routeID, "", "high", "repeated_waf_block_activity")
			d.blocks[event.routeID] = state
			if alert != nil {
				alerts = append(alerts, *alert)
			}
		}
	}
	return alerts
}

func (d *detector) reserveKey(now time.Time) bool {
	if len(d.rules)+len(d.blocks) < d.options.MaxKeys {
		return true
	}
	d.cleanup(now)
	if len(d.rules)+len(d.blocks) < d.options.MaxKeys {
		return true
	}
	d.keyDrops++
	return false
}

func (d *detector) update(state windowState, now time.Time, threshold int, detectorID, routeID, ruleID, severity, reason string) (windowState, *Alert) {
	if now.Before(state.windowStart) {
		now = state.windowStart
	}
	if now.Sub(state.windowStart) >= d.options.Window {
		state.windowStart, state.count = now, 0
	}
	state.count++
	if state.count < threshold || (!state.lastAlert.IsZero() && now.Sub(state.lastAlert) < d.options.Cooldown) {
		return state, nil
	}
	state.lastAlert = now
	return state, &Alert{schemaVersion: AlertSchemaV1, detectorID: detectorID, generatedAt: now,
		routeID: routeID, ruleID: ruleID, count: state.count, window: d.options.Window,
		severity: severity, reasonClass: reason}
}

func (d *detector) cleanup(now time.Time) {
	for key, state := range d.rules {
		if expiredState(state, now, d.options) {
			delete(d.rules, key)
		}
	}
	for key, state := range d.blocks {
		if expiredState(state, now, d.options) {
			delete(d.blocks, key)
		}
	}
}

func expiredState(state windowState, now time.Time, options DetectionOptions) bool {
	if now.Before(state.windowStart) || now.Sub(state.windowStart) < options.Window {
		return false
	}
	return state.lastAlert.IsZero() || (!now.Before(state.lastAlert) && now.Sub(state.lastAlert) >= options.Cooldown)
}

func (d *detector) activeKeys() int { return len(d.rules) + len(d.blocks) }
