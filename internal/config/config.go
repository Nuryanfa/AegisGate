package config

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

const (
	defaultEnvironment     = "development"
	defaultHTTPAddr        = ":8080"
	defaultReadTimeout     = 10 * time.Second
	defaultWriteTimeout    = 15 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 10 * time.Second
	defaultUpstreamURL     = "http://localhost:8081"
)

// Config contains the runtime settings required by the Sprint 0 gateway.
type Config struct {
	Environment     string
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	UpstreamURL     *url.URL
}

// Load reads configuration from environment variables and validates values
// that could make the server unsafe or unusable.
func Load() (Config, error) {
	readTimeout, err := duration("AEGIS_READ_TIMEOUT", defaultReadTimeout)
	if err != nil {
		return Config{}, err
	}

	writeTimeout, err := duration("AEGIS_WRITE_TIMEOUT", defaultWriteTimeout)
	if err != nil {
		return Config{}, err
	}

	idleTimeout, err := duration("AEGIS_IDLE_TIMEOUT", defaultIdleTimeout)
	if err != nil {
		return Config{}, err
	}

	shutdownTimeout, err := duration("AEGIS_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return Config{}, err
	}

	upstream, err := parseUpstream(env("AEGIS_UPSTREAM_URL", defaultUpstreamURL))
	if err != nil {
		return Config{}, err
	}

	httpAddr := env("AEGIS_HTTP_ADDR", defaultHTTPAddr)
	if httpAddr == "" {
		return Config{}, fmt.Errorf("AEGIS_HTTP_ADDR must not be empty")
	}

	return Config{
		Environment:     env("AEGIS_ENV", defaultEnvironment),
		HTTPAddr:        httpAddr,
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		IdleTimeout:     idleTimeout,
		ShutdownTimeout: shutdownTimeout,
		UpstreamURL:     upstream,
	}, nil
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func duration(key string, fallback time.Duration) (time.Duration, error) {
	raw := env(key, fallback.String())
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
	}
	return value, nil
}

func parseUpstream(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse AEGIS_UPSTREAM_URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("AEGIS_UPSTREAM_URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("AEGIS_UPSTREAM_URL must include a host")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("AEGIS_UPSTREAM_URL must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("AEGIS_UPSTREAM_URL must not include a query or fragment")
	}
	return parsed, nil
}
