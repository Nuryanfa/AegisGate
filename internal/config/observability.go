package config

import (
	"errors"

	"github.com/Nuryanfa/AegisGate/internal/observability"
)

type fileObservability struct {
	ServiceName string       `yaml:"service_name"`
	Environment string       `yaml:"environment"`
	Metrics     *fileMetrics `yaml:"metrics"`
	Tracing     *fileTracing `yaml:"tracing"`
}

type fileMetrics struct {
	Enabled         bool   `yaml:"enabled"`
	Address         string `yaml:"address"`
	Path            string `yaml:"path"`
	ReadTimeout     string `yaml:"read_timeout"`
	WriteTimeout    string `yaml:"write_timeout"`
	ShutdownTimeout string `yaml:"shutdown_timeout"`
}

type fileTracing struct {
	Enabled            bool     `yaml:"enabled"`
	Endpoint           string   `yaml:"endpoint"`
	SampleRatio        *float64 `yaml:"sample_ratio"`
	ExportTimeout      string   `yaml:"export_timeout"`
	BatchTimeout       string   `yaml:"batch_timeout"`
	MaxQueueSize       int      `yaml:"max_queue_size"`
	MaxExportBatchSize int      `yaml:"max_export_batch_size"`
	ShutdownTimeout    string   `yaml:"shutdown_timeout"`
}

func parseObservability(raw fileObservability) (observability.Options, error) {
	options := observability.Options{ServiceName: raw.ServiceName, Environment: raw.Environment}
	if raw.Metrics != nil {
		m := raw.Metrics
		if !m.Enabled {
			if m.Address != "" || m.Path != "" || m.ReadTimeout != "" || m.WriteTimeout != "" || m.ShutdownTimeout != "" {
				return options, errors.New("disabled observability.metrics must not define unused settings")
			}
		} else {
			var err error
			options.Metrics = observability.MetricsOptions{Enabled: true, Address: m.Address, Path: m.Path}
			if options.Metrics.ReadTimeout, err = requiredDuration("observability.metrics.read_timeout", m.ReadTimeout); err != nil {
				return options, err
			}
			if options.Metrics.WriteTimeout, err = requiredDuration("observability.metrics.write_timeout", m.WriteTimeout); err != nil {
				return options, err
			}
			if options.Metrics.ShutdownTimeout, err = requiredDuration("observability.metrics.shutdown_timeout", m.ShutdownTimeout); err != nil {
				return options, err
			}
		}
	}
	if raw.Tracing != nil {
		t := raw.Tracing
		if !t.Enabled {
			if t.Endpoint != "" || t.SampleRatio != nil || t.ExportTimeout != "" || t.BatchTimeout != "" || t.MaxQueueSize != 0 || t.MaxExportBatchSize != 0 || t.ShutdownTimeout != "" {
				return options, errors.New("disabled observability.tracing must not define unused settings")
			}
		} else {
			if t.SampleRatio == nil {
				return options, errors.New("observability.tracing.sample_ratio is required")
			}
			var err error
			options.Tracing = observability.TracingOptions{Enabled: true, Endpoint: t.Endpoint, SampleRatio: *t.SampleRatio,
				MaxQueueSize: t.MaxQueueSize, MaxExportBatchSize: t.MaxExportBatchSize}
			if options.Tracing.ExportTimeout, err = requiredDuration("observability.tracing.export_timeout", t.ExportTimeout); err != nil {
				return options, err
			}
			if options.Tracing.BatchTimeout, err = requiredDuration("observability.tracing.batch_timeout", t.BatchTimeout); err != nil {
				return options, err
			}
			if options.Tracing.ShutdownTimeout, err = requiredDuration("observability.tracing.shutdown_timeout", t.ShutdownTimeout); err != nil {
				return options, err
			}
		}
	}
	if err := options.Validate(); err != nil {
		return options, err
	}
	return options, nil
}
