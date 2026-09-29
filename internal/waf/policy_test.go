package waf

import "testing"

func TestPolicyValidation(t *testing.T) {
	valid := Inspection{Query: true, Headers: true, Body: true, MaxQueryBytes: 1024, MaxHeaderBytes: 2048, MaxBodyBytes: 4096, MaxJSONDepth: 8, MaxJSONElements: 100}
	tests := []struct {
		name, mode, rules string
		threshold         int
		inspection        Inspection
		wantError         bool
	}{
		{"disabled", "disabled", "", 0, Inspection{}, false},
		{"audit", "audit", RuleSetCoreV1, 5, valid, false},
		{"enforce", "enforce", RuleSetCoreV1, 5, valid, false},
		{"unknown mode", "observe", RuleSetCoreV1, 5, valid, true},
		{"unknown rules", "audit", "core-v2", 5, valid, true},
		{"zero threshold", "audit", RuleSetCoreV1, 0, valid, true},
		{"large threshold", "audit", RuleSetCoreV1, MaxAnomalyThreshold + 1, valid, true},
		{"missing query limit", "audit", RuleSetCoreV1, 5, Inspection{Query: true}, true},
		{"unused query limit", "audit", RuleSetCoreV1, 5, Inspection{MaxQueryBytes: 1}, true},
		{"excessive body", "audit", RuleSetCoreV1, 5, Inspection{Body: true, MaxBodyBytes: MaxBodyBytes + 1, MaxJSONDepth: 1, MaxJSONElements: 1}, true},
		{"disabled contradiction", "disabled", RuleSetCoreV1, 5, valid, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPolicy(tt.mode, tt.rules, tt.threshold, tt.inspection)
			if (err != nil) != tt.wantError {
				t.Fatalf("NewPolicy() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
