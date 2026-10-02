// Package waf provides bounded request inspection for route-level policies.
package waf

import (
	"errors"
	"fmt"
)

const (
	RuleSetCoreV1 = "core-v1"

	MaxAnomalyThreshold = 100
	MaxQueryBytes       = 64 << 10
	MaxHeaderBytes      = 64 << 10
	MaxBodyBytes        = 2 << 20
	MaxJSONDepth        = 64
	MaxJSONElements     = 10_000
)

type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModeAudit    Mode = "audit"
	ModeEnforce  Mode = "enforce"
)

// Inspection defines the explicitly enabled request locations and hard limits.
type Inspection struct {
	Query           bool
	Headers         bool
	Body            bool
	MaxQueryBytes   int
	MaxHeaderBytes  int
	MaxBodyBytes    int
	MaxJSONDepth    int
	MaxJSONElements int
}

// Policy is immutable after construction and safe for concurrent use.
type Policy struct {
	mode      Mode
	ruleSet   string
	threshold int
	inspect   Inspection
}

func NewPolicy(mode, ruleSet string, threshold int, inspection Inspection) (Policy, error) {
	p := Policy{mode: Mode(mode), ruleSet: ruleSet, threshold: threshold, inspect: inspection}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	switch p.mode {
	case ModeDisabled:
		if p.ruleSet != "" || p.threshold != 0 || p.inspect != (Inspection{}) {
			return errors.New("disabled mode must not define a rule set, threshold, or inspection settings")
		}
		return nil
	case ModeAudit, ModeEnforce:
	default:
		if p.mode == "" {
			return errors.New("mode is required")
		}
		return fmt.Errorf("unsupported mode %q", p.mode)
	}
	if p.ruleSet != RuleSetCoreV1 {
		return fmt.Errorf("unsupported rule_set %q", p.ruleSet)
	}
	if p.threshold < 1 || p.threshold > MaxAnomalyThreshold {
		return fmt.Errorf("anomaly_threshold must be between 1 and %d", MaxAnomalyThreshold)
	}
	if err := validateOptionalLimit("max_query_bytes", p.inspect.Query, p.inspect.MaxQueryBytes, MaxQueryBytes); err != nil {
		return err
	}
	if err := validateOptionalLimit("max_header_bytes", p.inspect.Headers, p.inspect.MaxHeaderBytes, MaxHeaderBytes); err != nil {
		return err
	}
	if p.inspect.Body {
		for _, limit := range []struct {
			name, unit string
			value, max int
		}{
			{"max_body_bytes", "bytes", p.inspect.MaxBodyBytes, MaxBodyBytes},
			{"max_json_depth", "levels", p.inspect.MaxJSONDepth, MaxJSONDepth},
			{"max_json_elements", "elements", p.inspect.MaxJSONElements, MaxJSONElements},
		} {
			if limit.value < 1 || limit.value > limit.max {
				return fmt.Errorf("%s must be between 1 and %d %s when body inspection is enabled", limit.name, limit.max, limit.unit)
			}
		}
	} else if p.inspect.MaxBodyBytes != 0 || p.inspect.MaxJSONDepth != 0 || p.inspect.MaxJSONElements != 0 {
		return errors.New("body inspection limits require body inspection to be enabled")
	}
	return nil
}

func validateOptionalLimit(name string, enabled bool, value, maximum int) error {
	if enabled {
		if value < 1 || value > maximum {
			return fmt.Errorf("%s must be between 1 and %d when inspection is enabled", name, maximum)
		}
		return nil
	}
	if value != 0 {
		return fmt.Errorf("%s requires its inspection location to be enabled", name)
	}
	return nil
}

func (p Policy) Mode() Mode             { return p.mode }
func (p Policy) RuleSet() string        { return p.ruleSet }
func (p Policy) AnomalyThreshold() int  { return p.threshold }
func (p Policy) Inspection() Inspection { return p.inspect }
func (p Policy) Enabled() bool          { return p.mode != ModeDisabled }
func (p Policy) Enforces() bool         { return p.mode == ModeEnforce }
