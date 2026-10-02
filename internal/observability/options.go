package observability

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type MetricsOptions struct {
	Enabled         bool
	Address         string
	Path            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type TracingOptions struct {
	Enabled            bool
	Endpoint           string
	SampleRatio        float64
	ExportTimeout      time.Duration
	BatchTimeout       time.Duration
	MaxQueueSize       int
	MaxExportBatchSize int
	ShutdownTimeout    time.Duration
}

type Options struct {
	ServiceName string
	Environment string
	Metrics     MetricsOptions
	Tracing     TracingOptions
}

func (o Options) Validate() error {
	if !o.Metrics.Enabled && !o.Tracing.Enabled {
		return errors.New("observability requires metrics or tracing to be enabled")
	}
	for name, value := range map[string]string{"service_name": o.ServiceName, "environment": o.Environment} {
		if len(value) == 0 || len(value) > 64 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != "" {
			return fmt.Errorf("observability.%s must be 1-64 ASCII letters, digits, hyphens, underscores or dots", name)
		}
	}
	if o.Metrics.Enabled {
		host, port, err := net.SplitHostPort(o.Metrics.Address)
		if err != nil || host == "" {
			return errors.New("observability.metrics.address must be host:port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("observability.metrics.address has invalid TCP port")
		}
		p := o.Metrics.Path
		if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\\%") || strings.Contains(p, "//") || path.Clean(p) != p {
			return errors.New("observability.metrics.path must be an absolute canonical path")
		}
		for _, field := range []struct {
			name  string
			value time.Duration
		}{
			{"read_timeout", o.Metrics.ReadTimeout}, {"write_timeout", o.Metrics.WriteTimeout}, {"shutdown_timeout", o.Metrics.ShutdownTimeout},
		} {
			if field.value <= 0 || field.value > 30*time.Second {
				return fmt.Errorf("observability.metrics.%s must be positive and at most 30s", field.name)
			}
		}
	} else if o.Metrics != (MetricsOptions{}) {
		return errors.New("disabled observability.metrics must not define unused settings")
	}
	if o.Tracing.Enabled {
		u, err := url.Parse(o.Tracing.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return errors.New("observability.tracing.endpoint must be an HTTP base URL without credentials, path, query or fragment")
		}
		if math.IsNaN(o.Tracing.SampleRatio) || math.IsInf(o.Tracing.SampleRatio, 0) || o.Tracing.SampleRatio < 0 || o.Tracing.SampleRatio > 1 {
			return errors.New("observability.tracing.sample_ratio must be between 0 and 1")
		}
		for _, field := range []struct {
			name  string
			value time.Duration
		}{
			{"export_timeout", o.Tracing.ExportTimeout}, {"batch_timeout", o.Tracing.BatchTimeout}, {"shutdown_timeout", o.Tracing.ShutdownTimeout},
		} {
			if field.value <= 0 || field.value > 30*time.Second {
				return fmt.Errorf("observability.tracing.%s must be positive and at most 30s", field.name)
			}
		}
		if o.Tracing.MaxQueueSize < 1 || o.Tracing.MaxQueueSize > 65536 || o.Tracing.MaxExportBatchSize < 1 || o.Tracing.MaxExportBatchSize > 4096 || o.Tracing.MaxExportBatchSize > o.Tracing.MaxQueueSize {
			return errors.New("observability.tracing batch and queue sizes must be positive, bounded, and batch must not exceed queue")
		}
	} else if o.Tracing != (TracingOptions{}) {
		return errors.New("disabled observability.tracing must not define unused settings")
	}
	return nil
}
