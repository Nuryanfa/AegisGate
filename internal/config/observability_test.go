package config

import (
	"strings"
	"testing"
)

const metricsConfig = `observability:
  service_name: aegisgate
  environment: test
  metrics:
    enabled: true
    address: "127.0.0.1:9090"
    path: /metrics
    read_timeout: 5s
    write_timeout: 10s
    shutdown_timeout: 5s
`

const tracingConfig = `observability:
  service_name: aegisgate
  environment: test
  tracing:
    enabled: true
    endpoint: http://localhost:4318
    sample_ratio: 0.1
    export_timeout: 2s
    batch_timeout: 5s
    max_queue_size: 128
    max_export_batch_size: 32
    shutdown_timeout: 5s
`

func TestObservabilityConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, block      string
		metrics, tracing bool
	}{
		{"omitted v0.6", "", false, false},
		{"metrics only", metricsConfig, true, false},
		{"tracing only", tracingConfig, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prepareEnvironment(t)
			t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, tt.block+validConfig()))
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if tt.block == "" {
				if cfg.Observability != nil {
					t.Fatal("omitted observability enabled")
				}
				return
			}
			if cfg.Observability == nil || cfg.Observability.Metrics.Enabled != tt.metrics || cfg.Observability.Tracing.Enabled != tt.tracing {
				t.Fatalf("unexpected options: %#v", cfg.Observability)
			}
		})
	}
}

func TestObservabilityConfigurationRejectsInvalid(t *testing.T) {
	for _, tt := range []struct{ name, block string }{
		{"negative ratio", strings.Replace(tracingConfig, "sample_ratio: 0.1", "sample_ratio: -0.1", 1)},
		{"ratio too large", strings.Replace(tracingConfig, "sample_ratio: 0.1", "sample_ratio: 1.1", 1)},
		{"missing ratio", strings.Replace(tracingConfig, "    sample_ratio: 0.1\n", "", 1)},
		{"zero duration", strings.Replace(metricsConfig, "read_timeout: 5s", "read_timeout: 0s", 1)},
		{"excessive duration", strings.Replace(metricsConfig, "read_timeout: 5s", "read_timeout: 31s", 1)},
		{"bad path", strings.Replace(metricsConfig, "path: /metrics", "path: metrics", 1)},
		{"unknown field", strings.Replace(metricsConfig, "    path: /metrics", "    mystery: true\n    path: /metrics", 1)},
		{"batch over queue", strings.Replace(tracingConfig, "max_export_batch_size: 32", "max_export_batch_size: 129", 1)},
		{"zero queue", strings.Replace(tracingConfig, "max_queue_size: 128", "max_queue_size: 0", 1)},
		{"disabled with values", strings.Replace(metricsConfig, "enabled: true", "enabled: false", 1)},
		{"no enabled feature", "observability:\n  service_name: aegisgate\n  environment: test\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prepareEnvironment(t)
			t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, tt.block+validConfig()))
			if _, err := Load(); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
