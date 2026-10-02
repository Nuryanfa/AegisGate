package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/securityevent"
	"github.com/Nuryanfa/AegisGate/internal/waf"
	"go.yaml.in/yaml/v3"
)

const (
	maxConfigBytes             = 1 << 20
	defaultEnvironment         = "development"
	defaultHTTPAddr            = ":8080"
	defaultReadTimeout         = 10 * time.Second
	defaultWriteTimeout        = 15 * time.Second
	defaultIdleTimeout         = 60 * time.Second
	defaultShutdownTimeout     = 10 * time.Second
	defaultRedisConnectTimeout = 2 * time.Second
	defaultRedisCommandTimeout = 500 * time.Millisecond
	maxRedisTimeout            = 10 * time.Second
	defaultRedisPoolSize       = 20
	maxRedisPoolSize           = 1000
)

// Config contains the validated runtime settings for AegisGate.
type Config struct {
	Environment     string
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Redis           *RedisConfig
	SecurityEvents  *securityevent.Options
	Observability   *observability.Options
	APIKeys         []auth.Key
	Routes          []router.Route
}

type fileConfig struct {
	Server         fileServer          `yaml:"server"`
	Redis          *fileRedis          `yaml:"redis"`
	SecurityEvents *fileSecurityEvents `yaml:"security_events"`
	Observability  *fileObservability  `yaml:"observability"`
	APIKeys        []fileAPIKey        `yaml:"api_keys"`
	Routes         []fileRoute         `yaml:"routes"`
}

type fileSecurityEvents struct {
	QueueCapacity    int            `yaml:"queue_capacity"`
	DeliveryCapacity int            `yaml:"delivery_capacity"`
	Workers          int            `yaml:"workers"`
	SinkTimeout      string         `yaml:"sink_timeout"`
	ShutdownTimeout  string         `yaml:"shutdown_timeout"`
	SummaryInterval  string         `yaml:"summary_interval"`
	Detection        *fileDetection `yaml:"detection"`
}

type fileDetection struct {
	Enabled            *bool  `yaml:"enabled"`
	Window             string `yaml:"window"`
	RuleMatchThreshold int    `yaml:"rule_match_threshold"`
	BlockThreshold     int    `yaml:"block_threshold"`
	Cooldown           string `yaml:"cooldown"`
	MaxKeys            int    `yaml:"max_keys"`
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
	ID         string         `yaml:"id"`
	PathPrefix string         `yaml:"path_prefix"`
	Upstream   string         `yaml:"upstream"`
	Timeout    string         `yaml:"timeout"`
	Auth       fileAuth       `yaml:"auth"`
	RateLimit  *fileRateLimit `yaml:"rate_limit"`
	WAF        *fileWAF       `yaml:"waf"`
}

type fileWAF struct {
	Mode             string          `yaml:"mode"`
	RuleSet          string          `yaml:"rule_set"`
	AnomalyThreshold int             `yaml:"anomaly_threshold"`
	Inspection       *fileInspection `yaml:"inspection"`
}

type fileInspection struct {
	Query           bool `yaml:"query"`
	Headers         bool `yaml:"headers"`
	Body            bool `yaml:"body"`
	MaxQueryBytes   *int `yaml:"max_query_bytes"`
	MaxHeaderBytes  *int `yaml:"max_header_bytes"`
	MaxBodyBytes    *int `yaml:"max_body_bytes"`
	MaxJSONDepth    *int `yaml:"max_json_depth"`
	MaxJSONElements *int `yaml:"max_json_elements"`
}

type RedisConfig struct {
	Address        string
	Username       string
	Password       string
	Database       int
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	PoolSize       int
}

type fileRedis struct {
	Address        string `yaml:"address"`
	Database       int    `yaml:"database"`
	ConnectTimeout string `yaml:"connect_timeout"`
	CommandTimeout string `yaml:"command_timeout"`
	PoolSize       int    `yaml:"pool_size"`
}

type fileRateLimit struct {
	Capacity        int64   `yaml:"capacity"`
	RefillPerSecond float64 `yaml:"refill_per_second"`
	OnRedisError    string  `yaml:"on_redis_error"`
}

type fileAuth struct {
	Mode           string   `yaml:"mode"`
	RequiredScopes []string `yaml:"required_scopes"`
}

type fileAPIKey struct {
	ID     string   `yaml:"id"`
	SHA256 string   `yaml:"sha256"`
	Scopes []string `yaml:"scopes"`
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
	if err := validateTimeoutRelationships(cfg); err != nil {
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
	if raw.Redis != nil {
		redisConfig, err := parseRedis(*raw.Redis)
		if err != nil {
			return Config{}, err
		}
		cfg.Redis = &redisConfig
	}

	cfg.APIKeys = make([]auth.Key, 0, len(raw.APIKeys))
	for index, rawKey := range raw.APIKeys {
		key, err := auth.NewKey(rawKey.ID, rawKey.SHA256, rawKey.Scopes)
		if err != nil {
			return Config{}, fmt.Errorf("api_keys[%d]: %w", index, err)
		}
		cfg.APIKeys = append(cfg.APIKeys, key)
	}
	if _, err := auth.NewRegistry(cfg.APIKeys); err != nil {
		return Config{}, fmt.Errorf("validate API key registry: %w", err)
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
	for _, route := range cfg.Routes {
		if route.Auth.RequiresAPIKey() && len(cfg.APIKeys) == 0 {
			return Config{}, fmt.Errorf("route %q requires API key authentication but api_keys is empty", route.ID)
		}
	}
	hasRateLimit := false
	for _, route := range cfg.Routes {
		if route.RateLimit != nil {
			hasRateLimit = true
			break
		}
	}
	if hasRateLimit && cfg.Redis == nil {
		return Config{}, errors.New("redis configuration is required when any route enables rate limiting")
	}
	if !hasRateLimit && cfg.Redis != nil {
		return Config{}, errors.New("redis configuration is unused because no route enables rate limiting")
	}
	hasWAF := false
	for _, route := range cfg.Routes {
		if route.WAF != nil && route.WAF.Enabled() {
			hasWAF = true
			break
		}
	}
	if hasWAF {
		options := securityevent.DefaultOptions()
		if raw.SecurityEvents != nil {
			parsed, err := parseSecurityEvents(*raw.SecurityEvents)
			if err != nil {
				return Config{}, err
			}
			options = parsed
		}
		cfg.SecurityEvents = &options
	} else if raw.SecurityEvents != nil {
		return Config{}, errors.New("security_events configuration is unused because no route enables WAF inspection")
	}
	if raw.Observability != nil {
		options, err := parseObservability(*raw.Observability)
		if err != nil {
			return Config{}, err
		}
		cfg.Observability = &options
	}

	return cfg, nil
}

func parseSecurityEvents(raw fileSecurityEvents) (securityevent.Options, error) {
	if raw.Detection == nil {
		return securityevent.Options{}, errors.New("security_events.detection is required")
	}
	sinkTimeout, err := requiredDuration("security_events.sink_timeout", raw.SinkTimeout)
	if err != nil {
		return securityevent.Options{}, err
	}
	shutdownTimeout, err := requiredDuration("security_events.shutdown_timeout", raw.ShutdownTimeout)
	if err != nil {
		return securityevent.Options{}, err
	}
	summaryInterval, err := requiredDuration("security_events.summary_interval", raw.SummaryInterval)
	if err != nil {
		return securityevent.Options{}, err
	}
	detection, err := parseDetection(*raw.Detection)
	if err != nil {
		return securityevent.Options{}, err
	}
	options := securityevent.Options{
		QueueCapacity: raw.QueueCapacity, DeliveryCapacity: raw.DeliveryCapacity, Workers: raw.Workers,
		SinkTimeout: sinkTimeout, ShutdownTimeout: shutdownTimeout, SummaryInterval: summaryInterval,
		Detection: detection,
	}
	if err := options.Validate(); err != nil {
		return securityevent.Options{}, err
	}
	return options, nil
}

func parseDetection(raw fileDetection) (securityevent.DetectionOptions, error) {
	if raw.Enabled == nil {
		return securityevent.DetectionOptions{}, errors.New("security_events.detection.enabled is required")
	}
	if !*raw.Enabled {
		options := securityevent.DetectionOptions{Enabled: false}
		if raw.Window != "" || raw.RuleMatchThreshold != 0 || raw.BlockThreshold != 0 || raw.Cooldown != "" || raw.MaxKeys != 0 {
			return options, errors.New("disabled security-event detection must not define unused settings")
		}
		return options, nil
	}
	window, err := requiredDuration("security_events.detection.window", raw.Window)
	if err != nil {
		return securityevent.DetectionOptions{}, err
	}
	cooldown, err := requiredDuration("security_events.detection.cooldown", raw.Cooldown)
	if err != nil {
		return securityevent.DetectionOptions{}, err
	}
	options := securityevent.DetectionOptions{Enabled: true, Window: window,
		RuleMatchThreshold: raw.RuleMatchThreshold, BlockThreshold: raw.BlockThreshold,
		Cooldown: cooldown, MaxKeys: raw.MaxKeys}
	if err := options.Validate(); err != nil {
		return securityevent.DetectionOptions{}, err
	}
	return options, nil
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
	policy, err := auth.NewPolicy(raw.Auth.Mode, raw.Auth.RequiredScopes)
	if err != nil {
		return router.Route{}, fmt.Errorf("%s.auth: %w", label, err)
	}
	var rateLimitPolicy *ratelimit.Policy
	if raw.RateLimit != nil {
		parsed, err := ratelimit.NewPolicy(raw.RateLimit.Capacity, raw.RateLimit.RefillPerSecond, raw.RateLimit.OnRedisError)
		if err != nil {
			return router.Route{}, fmt.Errorf("%s.rate_limit: %w", label, err)
		}
		rateLimitPolicy = &parsed
	}
	var wafPolicy *waf.Policy
	if raw.WAF != nil {
		parsed, err := parseWAF(*raw.WAF)
		if err != nil {
			return router.Route{}, fmt.Errorf("%s.waf: %w", label, err)
		}
		wafPolicy = &parsed
	}

	return router.Route{
		ID:         raw.ID,
		PathPrefix: raw.PathPrefix,
		Upstream:   upstream.String(),
		Timeout:    timeout,
		Auth:       policy,
		RateLimit:  rateLimitPolicy,
		WAF:        wafPolicy,
	}, nil
}

func parseWAF(raw fileWAF) (waf.Policy, error) {
	if raw.Mode == string(waf.ModeDisabled) {
		if raw.RuleSet != "" || raw.AnomalyThreshold != 0 || raw.Inspection != nil {
			return waf.Policy{}, errors.New("disabled mode must not define rule_set, anomaly_threshold, or inspection")
		}
		return waf.NewPolicy(raw.Mode, "", 0, waf.Inspection{})
	}
	if raw.Inspection == nil {
		return waf.Policy{}, errors.New("inspection is required when WAF is enabled")
	}
	inspection := waf.Inspection{
		Query: raw.Inspection.Query, Headers: raw.Inspection.Headers, Body: raw.Inspection.Body,
		MaxQueryBytes:   valueOrZero(raw.Inspection.MaxQueryBytes),
		MaxHeaderBytes:  valueOrZero(raw.Inspection.MaxHeaderBytes),
		MaxBodyBytes:    valueOrZero(raw.Inspection.MaxBodyBytes),
		MaxJSONDepth:    valueOrZero(raw.Inspection.MaxJSONDepth),
		MaxJSONElements: valueOrZero(raw.Inspection.MaxJSONElements),
	}
	return waf.NewPolicy(raw.Mode, raw.RuleSet, raw.AnomalyThreshold, inspection)
}

func valueOrZero(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func parseRedis(raw fileRedis) (RedisConfig, error) {
	if strings.TrimSpace(raw.Address) != raw.Address || raw.Address == "" {
		return RedisConfig{}, errors.New("redis.address must be non-empty without surrounding whitespace")
	}
	host, port, err := net.SplitHostPort(raw.Address)
	if err != nil || host == "" {
		return RedisConfig{}, errors.New("redis.address must use host:port format")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return RedisConfig{}, errors.New("redis.address must contain a valid TCP port")
	}
	if raw.Database < 0 || raw.Database > 1024 {
		return RedisConfig{}, errors.New("redis.database must be between 0 and 1024")
	}
	connectTimeout, err := optionalBoundedDuration("redis.connect_timeout", raw.ConnectTimeout, defaultRedisConnectTimeout, maxRedisTimeout)
	if err != nil {
		return RedisConfig{}, err
	}
	commandTimeout, err := optionalBoundedDuration("redis.command_timeout", raw.CommandTimeout, defaultRedisCommandTimeout, maxRedisTimeout)
	if err != nil {
		return RedisConfig{}, err
	}
	poolSize := raw.PoolSize
	if poolSize == 0 {
		poolSize = defaultRedisPoolSize
	}
	if poolSize < 1 || poolSize > maxRedisPoolSize {
		return RedisConfig{}, fmt.Errorf("redis.pool_size must be between 1 and %d", maxRedisPoolSize)
	}
	return RedisConfig{
		Address:        raw.Address,
		Database:       raw.Database,
		ConnectTimeout: connectTimeout,
		CommandTimeout: commandTimeout,
		PoolSize:       poolSize,
	}, nil
}

func validateTimeoutRelationships(cfg Config) error {
	for _, route := range cfg.Routes {
		if route.Timeout >= cfg.WriteTimeout {
			return fmt.Errorf("route %q timeout %s must be less than server.write_timeout %s", route.ID, route.Timeout, cfg.WriteTimeout)
		}
	}
	return nil
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
	if cfg.Redis != nil {
		if username, ok := os.LookupEnv("AEGIS_REDIS_USERNAME"); ok {
			cfg.Redis.Username = username
		}
		if password, ok := os.LookupEnv("AEGIS_REDIS_PASSWORD"); ok {
			cfg.Redis.Password = password
		}
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

func optionalBoundedDuration(name, raw string, fallback, maximum time.Duration) (time.Duration, error) {
	value, err := optionalDuration(name, raw, fallback)
	if err != nil {
		return 0, err
	}
	if value > maximum {
		return 0, fmt.Errorf("%s must not exceed %s", name, maximum)
	}
	return value, nil
}
