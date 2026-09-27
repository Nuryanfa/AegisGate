package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/router"
	"go.yaml.in/yaml/v3"
)

const (
	maxConfigBytes         = 1 << 20
	defaultEnvironment     = "development"
	defaultHTTPAddr        = ":8080"
	defaultReadTimeout     = 10 * time.Second
	defaultWriteTimeout    = 15 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

// Config contains the validated runtime settings for AegisGate.
type Config struct {
	Environment     string
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Routes          []router.Route
}

type fileConfig struct {
	Server fileServer  `yaml:"server"`
	Routes []fileRoute `yaml:"routes"`
}

type fileServer struct {
	Environment     string `yaml:"environment"`
	Address         string `yaml:"address"`
	ReadTimeout     string `yaml:"read_timeout"`
	WriteTimeout    string `yaml:"write_timeout"`
	IdleTimeout     string `yaml:"idle_timeout"`
	ShutdownTimeout string `yaml:"shutdown_timeout"`
}

type fileRoute struct {
	ID         string `yaml:"id"`
	PathPrefix string `yaml:"path_prefix"`
	Upstream   string `yaml:"upstream"`
	Timeout    string `yaml:"timeout"`
}

// Load reads a strict YAML configuration selected by AEGIS_CONFIG_PATH.
// Server environment variables override file values; routes only come from
// the file so the active route table has one unambiguous source of truth.
func Load() (Config, error) {
	configPath, ok := os.LookupEnv("AEGIS_CONFIG_PATH")
	if !ok || strings.TrimSpace(configPath) == "" {
		return Config{}, errors.New("AEGIS_CONFIG_PATH must point to a configuration file")
	}
	if _, deprecated := os.LookupEnv("AEGIS_UPSTREAM_URL"); deprecated {
		return Config{}, errors.New("AEGIS_UPSTREAM_URL is no longer supported; define routes in the configuration file")
	}

	file, err := readFile(configPath)
	if err != nil {
		return Config{}, err
	}

	raw, err := decode(file)
	if err != nil {
		return Config{}, err
	}

	cfg, err := build(raw)
	if err != nil {
		return Config{}, err
	}
	if err := applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration file: %w", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration file: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return nil, fmt.Errorf("configuration file exceeds %d bytes", maxConfigBytes)
	}
	return contents, nil
}

func decode(contents []byte) (fileConfig, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)

	var raw fileConfig
	if err := decoder.Decode(&raw); err != nil {
		return fileConfig{}, fmt.Errorf("decode configuration YAML: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fileConfig{}, errors.New("configuration must contain exactly one YAML document")
		}
		return fileConfig{}, fmt.Errorf("decode configuration YAML: %w", err)
	}
	return raw, nil
}

func build(raw fileConfig) (Config, error) {
	cfg := Config{
		Environment:     valueOrDefault(raw.Server.Environment, defaultEnvironment),
		HTTPAddr:        valueOrDefault(raw.Server.Address, defaultHTTPAddr),
		ReadTimeout:     defaultReadTimeout,
		WriteTimeout:    defaultWriteTimeout,
		IdleTimeout:     defaultIdleTimeout,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if strings.TrimSpace(cfg.Environment) == "" {
		return Config{}, errors.New("server.environment must not be empty")
	}
	if strings.TrimSpace(cfg.HTTPAddr) == "" {
		return Config{}, errors.New("server.address must not be empty")
	}

	var err error
	if cfg.ReadTimeout, err = optionalDuration("server.read_timeout", raw.Server.ReadTimeout, defaultReadTimeout); err != nil {
		return Config{}, err
	}
	if cfg.WriteTimeout, err = optionalDuration("server.write_timeout", raw.Server.WriteTimeout, defaultWriteTimeout); err != nil {
		return Config{}, err
	}
	if cfg.IdleTimeout, err = optionalDuration("server.idle_timeout", raw.Server.IdleTimeout, defaultIdleTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = optionalDuration("server.shutdown_timeout", raw.Server.ShutdownTimeout, defaultShutdownTimeout); err != nil {
		return Config{}, err
	}

	if len(raw.Routes) == 0 {
		return Config{}, errors.New("configuration must define at least one route")
	}
	cfg.Routes = make([]router.Route, 0, len(raw.Routes))
	for index, rawRoute := range raw.Routes {
		route, err := parseRoute(index, rawRoute)
		if err != nil {
			return Config{}, err
		}
		cfg.Routes = append(cfg.Routes, route)
	}
	if _, err := router.New(cfg.Routes); err != nil {
		return Config{}, fmt.Errorf("validate routes: %w", err)
	}

	return cfg, nil
}

func parseRoute(index int, raw fileRoute) (router.Route, error) {
	label := fmt.Sprintf("routes[%d]", index)
	if raw.ID == "" || strings.TrimSpace(raw.ID) != raw.ID {
		return router.Route{}, fmt.Errorf("%s.id must be non-empty without surrounding whitespace", label)
	}
	if raw.PathPrefix == "/healthz" || raw.PathPrefix == "/readyz" {
		return router.Route{}, fmt.Errorf("%s.path_prefix %q is reserved by the gateway", label, raw.PathPrefix)
	}

	upstream, err := url.Parse(raw.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Opaque != "" {
		return router.Route{}, fmt.Errorf("%s upstream must be an absolute HTTP URL", label)
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return router.Route{}, fmt.Errorf("%s upstream scheme must be http or https", label)
	}
	if upstream.Host == "" {
		return router.Route{}, fmt.Errorf("%s upstream must include a host", label)
	}
	if upstream.User != nil {
		return router.Route{}, fmt.Errorf("%s upstream must not include credentials", label)
	}
	if upstream.RawQuery != "" || upstream.Fragment != "" {
		return router.Route{}, fmt.Errorf("%s upstream must not include a query or fragment", label)
	}

	timeout, err := requiredDuration(label+".timeout", raw.Timeout)
	if err != nil {
		return router.Route{}, err
	}

	return router.Route{
		ID:         raw.ID,
		PathPrefix: raw.PathPrefix,
		Upstream:   upstream.String(),
		Timeout:    timeout,
	}, nil
}

func applyEnvironment(cfg *Config) error {
	if value, ok := os.LookupEnv("AEGIS_ENV"); ok {
		if strings.TrimSpace(value) == "" {
			return errors.New("AEGIS_ENV must not be empty")
		}
		cfg.Environment = value
	}
	if value, ok := os.LookupEnv("AEGIS_HTTP_ADDR"); ok {
		if strings.TrimSpace(value) == "" {
			return errors.New("AEGIS_HTTP_ADDR must not be empty")
		}
		cfg.HTTPAddr = value
	}

	var err error
	if cfg.ReadTimeout, err = environmentDuration("AEGIS_READ_TIMEOUT", cfg.ReadTimeout); err != nil {
		return err
	}
	if cfg.WriteTimeout, err = environmentDuration("AEGIS_WRITE_TIMEOUT", cfg.WriteTimeout); err != nil {
		return err
	}
	if cfg.IdleTimeout, err = environmentDuration("AEGIS_IDLE_TIMEOUT", cfg.IdleTimeout); err != nil {
		return err
	}
	if cfg.ShutdownTimeout, err = environmentDuration("AEGIS_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout); err != nil {
		return err
	}
	return nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func optionalDuration(name, raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	return parsePositiveDuration(name, raw)
}

func requiredDuration(name, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("%s is required", name)
	}
	return parsePositiveDuration(name, raw)
}

func environmentDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	return parsePositiveDuration(name, raw)
}

func parsePositiveDuration(name, raw string) (time.Duration, error) {
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return value, nil
}
