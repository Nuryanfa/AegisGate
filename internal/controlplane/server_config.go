package controlplane

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

type ServerConfig struct {
	Address, SnapshotFile, MetricsAddress, Environment, TracingEndpoint string
	MaxClients, MaxMessageBytes                                         int
	ShutdownTimeout                                                     time.Duration
	TLS                                                                 ServerTLS
}

type ServerTLS struct {
	Enabled         bool   `yaml:"enabled"`
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile  string `yaml:"private_key_file"`
	ClientCAFile    string `yaml:"client_ca_file"`
}

func LoadServerConfig(path string) (ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("open control-plane configuration: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return ServerConfig{}, fmt.Errorf("read control-plane configuration: %w", err)
	}
	if len(data) > 1<<20 {
		return ServerConfig{}, errors.New("control-plane configuration exceeds 1 MiB")
	}
	var raw struct {
		Environment     string    `yaml:"environment"`
		Address         string    `yaml:"address"`
		MetricsAddress  string    `yaml:"metrics_address"`
		TracingEndpoint string    `yaml:"tracing_endpoint"`
		SnapshotFile    string    `yaml:"snapshot_file"`
		MaxClients      int       `yaml:"max_clients"`
		MaxMessageBytes int       `yaml:"max_message_bytes"`
		ShutdownTimeout string    `yaml:"shutdown_timeout"`
		TLS             ServerTLS `yaml:"tls"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return ServerConfig{}, fmt.Errorf("decode control-plane configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ServerConfig{}, errors.New("control-plane configuration must contain one YAML document")
	}
	if _, _, err := net.SplitHostPort(raw.Address); err != nil {
		return ServerConfig{}, errors.New("control-plane address must be host:port")
	}
	if raw.MetricsAddress != "" {
		if _, _, err := net.SplitHostPort(raw.MetricsAddress); err != nil {
			return ServerConfig{}, errors.New("metrics_address must be host:port")
		}
	}
	if raw.Environment != "development" && raw.Environment != "production" {
		return ServerConfig{}, errors.New("environment must be development or production")
	}
	if raw.TracingEndpoint != "" {
		u, err := url.Parse(raw.TracingEndpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ServerConfig{}, errors.New("tracing_endpoint must be an HTTP base URL without credentials")
		}
	}
	if raw.Environment == "production" && !raw.TLS.Enabled {
		return ServerConfig{}, errors.New("production control plane requires mTLS")
	}
	if raw.SnapshotFile == "" {
		return ServerConfig{}, errors.New("snapshot_file is required")
	}
	if raw.MaxClients < 1 || raw.MaxClients > 1024 {
		return ServerConfig{}, errors.New("max_clients must be 1-1024")
	}
	if raw.MaxMessageBytes < 1024 || raw.MaxMessageBytes > 2<<20 {
		return ServerConfig{}, errors.New("max_message_bytes must be 1024-2097152")
	}
	shutdown, err := time.ParseDuration(raw.ShutdownTimeout)
	if err != nil || shutdown <= 0 || shutdown > time.Minute {
		return ServerConfig{}, errors.New("shutdown_timeout must be positive and <=1m")
	}
	if raw.TLS.Enabled {
		if raw.TLS.CertificateFile == "" || raw.TLS.PrivateKeyFile == "" || raw.TLS.ClientCAFile == "" {
			return ServerConfig{}, errors.New("TLS requires certificate_file, private_key_file, and client_ca_file")
		}
	} else if raw.TLS.CertificateFile != "" || raw.TLS.PrivateKeyFile != "" || raw.TLS.ClientCAFile != "" {
		return ServerConfig{}, errors.New("TLS files require tls.enabled")
	}
	return ServerConfig{Address: raw.Address, SnapshotFile: raw.SnapshotFile, MetricsAddress: raw.MetricsAddress, Environment: raw.Environment, TracingEndpoint: raw.TracingEndpoint, MaxClients: raw.MaxClients, MaxMessageBytes: raw.MaxMessageBytes, ShutdownTimeout: shutdown, TLS: raw.TLS}, nil
}
