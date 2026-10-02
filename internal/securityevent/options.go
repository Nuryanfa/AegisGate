// Package securityevent implements a bounded, best-effort asynchronous
// security-event pipeline and process-local burst detector.
package securityevent

import (
	"errors"
	"fmt"
	"time"
)

const (
	MaxQueueCapacity = 65_536
	MaxWorkers       = 64
	MaxSinkTimeout   = 10 * time.Second
	MaxShutdownTime  = 30 * time.Second
	MaxSummaryPeriod = time.Hour
	MaxWindow        = time.Hour
	MaxCooldown      = 24 * time.Hour
	MaxThreshold     = 1_000_000
	MaxDetectionKeys = 65_536
)

type DetectionOptions struct {
	Enabled            bool
	Window             time.Duration
	RuleMatchThreshold int
	BlockThreshold     int
	Cooldown           time.Duration
	MaxKeys            int
}

type Options struct {
	QueueCapacity    int
	DeliveryCapacity int
	Workers          int
	SinkTimeout      time.Duration
	ShutdownTimeout  time.Duration
	SummaryInterval  time.Duration
	Detection        DetectionOptions
}

func DefaultOptions() Options {
	return Options{
		QueueCapacity: 1024, DeliveryCapacity: 1024, Workers: 2,
		SinkTimeout: time.Second, ShutdownTimeout: 5 * time.Second, SummaryInterval: 30 * time.Second,
		Detection: DetectionOptions{Enabled: true, Window: 30 * time.Second, RuleMatchThreshold: 10,
			BlockThreshold: 10, Cooldown: time.Minute, MaxKeys: 4096},
	}
}

func (o Options) Validate() error {
	for _, limit := range []struct {
		name       string
		value, max int
	}{
		{"queue_capacity", o.QueueCapacity, MaxQueueCapacity},
		{"delivery_capacity", o.DeliveryCapacity, MaxQueueCapacity},
		{"workers", o.Workers, MaxWorkers},
	} {
		if limit.value < 1 || limit.value > limit.max {
			return fmt.Errorf("security_events.%s must be between 1 and %d", limit.name, limit.max)
		}
	}
	for _, limit := range []struct {
		name           string
		value, maximum time.Duration
	}{
		{"sink_timeout", o.SinkTimeout, MaxSinkTimeout},
		{"shutdown_timeout", o.ShutdownTimeout, MaxShutdownTime},
		{"summary_interval", o.SummaryInterval, MaxSummaryPeriod},
	} {
		if limit.value <= 0 || limit.value > limit.maximum {
			return fmt.Errorf("security_events.%s must be positive and not exceed %s", limit.name, limit.maximum)
		}
	}
	return o.Detection.Validate()
}

func (o DetectionOptions) Validate() error {
	if !o.Enabled {
		if o.Window != 0 || o.RuleMatchThreshold != 0 || o.BlockThreshold != 0 || o.Cooldown != 0 || o.MaxKeys != 0 {
			return errors.New("disabled security-event detection must not define unused settings")
		}
		return nil
	}
	if o.Window <= 0 || o.Window > MaxWindow {
		return fmt.Errorf("security_events.detection.window must be positive and not exceed %s", MaxWindow)
	}
	if o.Cooldown <= 0 || o.Cooldown > MaxCooldown {
		return fmt.Errorf("security_events.detection.cooldown must be positive and not exceed %s", MaxCooldown)
	}
	if o.RuleMatchThreshold < 1 || o.RuleMatchThreshold > MaxThreshold {
		return fmt.Errorf("security_events.detection.rule_match_threshold must be between 1 and %d", MaxThreshold)
	}
	if o.BlockThreshold < 1 || o.BlockThreshold > MaxThreshold {
		return fmt.Errorf("security_events.detection.block_threshold must be between 1 and %d", MaxThreshold)
	}
	if o.MaxKeys < 1 || o.MaxKeys > MaxDetectionKeys {
		return fmt.Errorf("security_events.detection.max_keys must be between 1 and %d", MaxDetectionKeys)
	}
	return nil
}
