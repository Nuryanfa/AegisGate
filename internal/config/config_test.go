package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadValidConfigurationAndEnvironmentPrecedence(t *testing.T) {
	prepareEnvironment(t)
	path := writeConfig(t, `
server:
  environment: staging
  address: ":9000"
  read_timeout: 2s
  write_timeout: 3s
  idle_timeout: 4s
  shutdown_timeout: 5s
api_keys:
  - id: orders-client
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
    scopes: [orders:read]
routes:
  - id: users
    path_prefix: /api/users
    upstream: http://localhost:8081
    timeout: 750ms
    auth:
      mode: public
  - id: orders
    path_prefix: /api/orders
    upstream: http://localhost:8082/base
    timeout: 2s
    auth:
      mode: api_key
      required_scopes: [orders:read]
`)
	t.Setenv("AEGIS_CONFIG_PATH", path)
	t.Setenv("AEGIS_ENV", "production")
	t.Setenv("AEGIS_HTTP_ADDR", ":8080")
	t.Setenv("AEGIS_READ_TIMEOUT", "7s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != "production" || cfg.HTTPAddr != ":8080" {
		t.Fatalf("environment overrides not applied: %#v", cfg)
	}
	if cfg.ReadTimeout != 7*time.Second {
		t.Fatalf("ReadTimeout = %s, want 7s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 3*time.Second {
		t.Fatalf("WriteTimeout = %s, want file value 3s", cfg.WriteTimeout)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("len(Routes) = %d, want 2", len(cfg.Routes))
	}
	if len(cfg.APIKeys) != 1 {
		t.Fatalf("len(APIKeys) = %d, want 1", len(cfg.APIKeys))
	}
	if cfg.Routes[0].Auth.RequiresAPIKey() || !cfg.Routes[1].Auth.RequiresAPIKey() {
		t.Fatalf("route access policies were not loaded correctly")
	}
	if cfg.Redis != nil || cfg.Routes[0].RateLimit != nil || cfg.Routes[1].RateLimit != nil {
		t.Fatal("omitted rate-limit policy unexpectedly enabled Redis or limiting")
	}
	if cfg.Routes[0].PathPrefix != "/api/users" || cfg.Routes[0].Timeout != 750*time.Millisecond {
		t.Fatalf("first route = %#v", cfg.Routes[0])
	}
	if cfg.Routes[1].Upstream != "http://localhost:8082/base" {
		t.Fatalf("second upstream = %q", cfg.Routes[1].Upstream)
	}
}

func TestLoadRequiresReadableConfiguration(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		prepareEnvironment(t)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AEGIS_CONFIG_PATH") {
			t.Fatalf("Load() error = %v, want missing path error", err)
		}
	})

	t.Run("unreadable path", func(t *testing.T) {
		prepareEnvironment(t)
		t.Setenv("AEGIS_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "open configuration file") {
			t.Fatalf("Load() error = %v, want unreadable file error", err)
		}
	})
}

func TestLoadValidRateLimitAndRedisConfiguration(t *testing.T) {
	prepareEnvironment(t)
	t.Setenv("AEGIS_REDIS_USERNAME", "gateway")
	t.Setenv("AEGIS_REDIS_PASSWORD", "runtime-only-secret")
	t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, rateLimitedConfig(
		"redis:\n  address: localhost:6379\n  database: 2\n  connect_timeout: 1s\n  command_timeout: 250ms\n  pool_size: 25\n",
		"    rate_limit:\n      capacity: 20\n      refill_per_second: 5\n      on_redis_error: deny\n",
	)))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Redis == nil {
		t.Fatal("Redis configuration was not loaded")
	}
	if cfg.Redis.Address != "localhost:6379" || cfg.Redis.Database != 2 ||
		cfg.Redis.ConnectTimeout != time.Second || cfg.Redis.CommandTimeout != 250*time.Millisecond || cfg.Redis.PoolSize != 25 {
		t.Fatalf("Redis configuration = %#v", cfg.Redis)
	}
	if cfg.Redis.Username != "gateway" || cfg.Redis.Password != "runtime-only-secret" {
		t.Fatal("Redis credentials were not sourced from environment")
	}
	if cfg.Routes[0].RateLimit == nil || cfg.Routes[0].RateLimit.Capacity() != 20 || !cfg.Routes[0].RateLimit.FailClosed() {
		t.Fatalf("route rate-limit policy = %#v", cfg.Routes[0].RateLimit)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		configuration string
		wantError     string
	}{
		{name: "malformed YAML", configuration: "routes: [", wantError: "decode configuration YAML"},
		{name: "unknown field", configuration: validConfig() + "unknown: true\n", wantError: "field unknown not found"},
		{name: "multiple documents", configuration: validConfig() + "---\nroutes: []\n", wantError: "exactly one YAML document"},
		{name: "no routes", configuration: "routes: []\n", wantError: "at least one route"},
		{name: "invalid server timeout", configuration: "server:\n  read_timeout: 0s\n" + validConfig(), wantError: "must be greater than zero"},
		{name: "route timeout equals write timeout", configuration: "server:\n  write_timeout: 5s\n" + validConfig(), wantError: "must be less than server.write_timeout"},
		{name: "rate limit without Redis", configuration: rateLimitedConfig("", validRateLimitYAML()), wantError: "redis configuration is required"},
		{name: "unused Redis", configuration: "redis:\n  address: localhost:6379\n" + validConfig(), wantError: "redis configuration is unused"},
		{name: "invalid Redis address", configuration: rateLimitedConfig("redis:\n  address: redis\n", validRateLimitYAML()), wantError: "host:port"},
		{name: "invalid Redis port", configuration: rateLimitedConfig("redis:\n  address: redis:70000\n", validRateLimitYAML()), wantError: "valid TCP port"},
		{name: "negative Redis database", configuration: rateLimitedConfig("redis:\n  address: redis:6379\n  database: -1\n", validRateLimitYAML()), wantError: "between 0 and 1024"},
		{name: "excessive Redis timeout", configuration: rateLimitedConfig("redis:\n  address: redis:6379\n  command_timeout: 11s\n", validRateLimitYAML()), wantError: "must not exceed 10s"},
		{name: "negative Redis pool", configuration: rateLimitedConfig("redis:\n  address: redis:6379\n  pool_size: -1\n", validRateLimitYAML()), wantError: "pool_size must be between"},
		{name: "excessive Redis pool", configuration: rateLimitedConfig("redis:\n  address: redis:6379\n  pool_size: 1001\n", validRateLimitYAML()), wantError: "pool_size must be between"},
		{name: "zero rate capacity", configuration: rateLimitedConfig(validRedisYAML(), strings.Replace(validRateLimitYAML(), "capacity: 20", "capacity: 0", 1)), wantError: "capacity must be between"},
		{name: "excessive rate capacity", configuration: rateLimitedConfig(validRedisYAML(), strings.Replace(validRateLimitYAML(), "capacity: 20", "capacity: 1000001", 1)), wantError: "capacity must be between"},
		{name: "zero refill", configuration: rateLimitedConfig(validRedisYAML(), strings.Replace(validRateLimitYAML(), "refill_per_second: 5", "refill_per_second: 0", 1)), wantError: "refill_per_second must be between"},
		{name: "missing Redis failure mode", configuration: rateLimitedConfig(validRedisYAML(), strings.Replace(validRateLimitYAML(), "      on_redis_error: deny\n", "", 1)), wantError: "on_redis_error is required"},
		{name: "unknown Redis failure mode", configuration: rateLimitedConfig(validRedisYAML(), strings.Replace(validRateLimitYAML(), "deny", "maybe", 1)), wantError: "unsupported on_redis_error"},
		{name: "unknown rate-limit field", configuration: rateLimitedConfig(validRedisYAML(), validRateLimitYAML()+"      typo: true\n"), wantError: "field typo not found"},
		{name: "unknown Redis field", configuration: rateLimitedConfig("redis:\n  address: redis:6379\n  password: do-not-leak\n", validRateLimitYAML()), wantError: "field password not found"},
		{
			name: "duplicate IDs",
			configuration: routesConfig(
				publicRouteYAML("duplicate", "/one", "http://one.example", "1s") +
					publicRouteYAML("duplicate", "/two", "http://two.example", "1s")),
			wantError: "duplicate route ID",
		},
		{
			name: "duplicate prefixes",
			configuration: routesConfig(
				publicRouteYAML("one", "/same", "http://one.example", "1s") +
					publicRouteYAML("two", "/same", "http://two.example", "1s")),
			wantError: "duplicate route path prefix",
		},
		{name: "empty ID", configuration: singleRoute("", "/api", "http://api.example", "1s"), wantError: ".id must be non-empty"},
		{name: "empty prefix", configuration: singleRoute("api", "", "http://api.example", "1s"), wantError: "path prefix must be non-empty"},
		{name: "invalid prefix", configuration: singleRoute("api", "/api/../admin", "http://api.example", "1s"), wantError: "not canonical"},
		{name: "duplicate slash prefix", configuration: singleRoute("api", "/api//users", "http://api.example", "1s"), wantError: "not canonical"},
		{name: "trailing slash prefix", configuration: singleRoute("api", "/api/", "http://api.example", "1s"), wantError: "must not end with /"},
		{name: "reserved prefix", configuration: singleRoute("health", "/healthz", "http://api.example", "1s"), wantError: "reserved"},
		{name: "upstream missing scheme", configuration: singleRoute("api", "/api", "localhost:8081", "1s"), wantError: "absolute HTTP URL"},
		{name: "unsupported upstream", configuration: singleRoute("api", "/api", "file:///tmp/api", "1s"), wantError: "scheme must be http or https"},
		{name: "upstream credentials", configuration: singleRoute("api", "/api", "http://user:do-not-leak@api.example", "1s"), wantError: "must not include credentials"},
		{name: "upstream query", configuration: singleRoute("api", "/api", "http://api.example?token=value", "1s"), wantError: "must not include a query"},
		{name: "missing timeout", configuration: singleRoute("api", "/api", "http://api.example", ""), wantError: ".timeout is required"},
		{name: "zero timeout", configuration: singleRoute("api", "/api", "http://api.example", "0s"), wantError: "must be greater than zero"},
		{name: "negative timeout", configuration: singleRoute("api", "/api", "http://api.example", "-1s"), wantError: "must be greater than zero"},
		{name: "missing access mode", configuration: strings.Replace(validConfig(), "    auth:\n      mode: public\n", "", 1), wantError: "access mode is required"},
		{name: "unknown access mode", configuration: strings.Replace(validConfig(), "mode: public", "mode: magic", 1), wantError: "unknown access mode"},
		{name: "public route with scopes", configuration: strings.Replace(validConfig(), "mode: public", "mode: public\n      required_scopes: [orders:read]", 1), wantError: "public access mode cannot require scopes"},
		{name: "protected route without required scopes", configuration: strings.Replace(validConfig(), "mode: public", "mode: api_key", 1) + validAPIKeys(), wantError: "must require at least one scope"},
		{name: "duplicate required scopes", configuration: strings.Replace(validConfig(), "mode: public", "mode: api_key\n      required_scopes: [orders:read, orders:read]", 1) + validAPIKeys(), wantError: "duplicate scope"},
		{name: "invalid required scope", configuration: strings.Replace(validConfig(), "mode: public", "mode: api_key\n      required_scopes: ['bad scope']", 1) + validAPIKeys(), wantError: "scope must match"},
		{name: "protected route without keys", configuration: strings.Replace(validConfig(), "mode: public", "mode: api_key\n      required_scopes: [orders:read]", 1), wantError: "api_keys is empty"},
		{name: "unknown auth field", configuration: strings.Replace(validConfig(), "mode: public", "mode: public\n      typo: true", 1), wantError: "field typo not found"},
		{name: "invalid key ID", configuration: validConfig() + "api_keys:\n  - id: 'bad id'\n    sha256: " + strings.Repeat("0", 64) + "\n", wantError: "API key ID"},
		{name: "invalid key digest", configuration: validConfig() + "api_keys:\n  - id: client\n    sha256: not-a-digest\n", wantError: "exactly 64 hexadecimal"},
		{name: "invalid key scope", configuration: validConfig() + "api_keys:\n  - id: client\n    sha256: " + strings.Repeat("0", 64) + "\n    scopes: ['bad scope']\n", wantError: "scope must match"},
		{name: "empty key scopes", configuration: validConfig() + "api_keys:\n  - id: client\n    sha256: " + strings.Repeat("0", 64) + "\n", wantError: "must declare at least one scope"},
		{name: "duplicate key scope", configuration: validConfig() + "api_keys:\n  - id: client\n    sha256: " + strings.Repeat("0", 64) + "\n    scopes: [orders:read, orders:read]\n", wantError: "duplicate scope"},
		{name: "duplicate key IDs", configuration: validConfig() + duplicateKeysYAML("first", "first", strings.Repeat("0", 64), strings.Repeat("1", 64)), wantError: "duplicate API key ID"},
		{name: "duplicate key digests", configuration: validConfig() + duplicateKeysYAML("first", "second", strings.Repeat("0", 64), strings.Repeat("0", 64)), wantError: "duplicate API key SHA-256 digest"},
		{
			name:          "unenforced policy field",
			configuration: strings.Replace(validConfig(), "    timeout: 5s", "    timeout: 5s\n    auth_required: true", 1),
			wantError:     "field auth_required not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prepareEnvironment(t)
			t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, tt.configuration))

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.wantError)
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("Load() leaked upstream credential: %v", err)
			}
		})
	}
}

func TestLoadRejectsDeprecatedUpstreamEnvironment(t *testing.T) {
	prepareEnvironment(t)
	t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, validConfig()))
	t.Setenv("AEGIS_UPSTREAM_URL", "http://localhost:8081")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "no longer supported") {
		t.Fatalf("Load() error = %v, want migration error", err)
	}
}

func TestLoadRejectsInvalidEnvironmentOverride(t *testing.T) {
	prepareEnvironment(t)
	t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, validConfig()))
	t.Setenv("AEGIS_WRITE_TIMEOUT", "invalid")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AEGIS_WRITE_TIMEOUT") {
		t.Fatalf("Load() error = %v, want invalid environment duration error", err)
	}
}

func TestLoadRejectsEnvironmentWriteTimeoutNotAboveRouteTimeout(t *testing.T) {
	prepareEnvironment(t)
	t.Setenv("AEGIS_CONFIG_PATH", writeConfig(t, validConfig()))
	t.Setenv("AEGIS_WRITE_TIMEOUT", "5s")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must be less than server.write_timeout") {
		t.Fatalf("Load() error = %v, want route/write timeout relationship error", err)
	}
}

func validConfig() string {
	return singleRoute("users", "/api/users", "http://localhost:8081", "5s")
}

func routesConfig(routes string) string {
	return "routes:\n" + routes
}

func singleRoute(id, prefix, upstream, timeout string) string {
	return routesConfig(publicRouteYAML(id, prefix, upstream, timeout))
}

func publicRouteYAML(id, prefix, upstream, timeout string) string {
	return "  - id: " + id + "\n" +
		"    path_prefix: " + prefix + "\n" +
		"    upstream: " + upstream + "\n" +
		"    timeout: " + timeout + "\n" +
		"    auth:\n" +
		"      mode: public\n"
}

func validAPIKeys() string {
	return "api_keys:\n  - id: client\n    sha256: " + strings.Repeat("0", 64) + "\n    scopes: [orders:read]\n"
}

func duplicateKeysYAML(firstID, secondID, firstDigest, secondDigest string) string {
	return "api_keys:\n" +
		"  - id: " + firstID + "\n    sha256: " + firstDigest + "\n    scopes: [orders:read]\n" +
		"  - id: " + secondID + "\n    sha256: " + secondDigest + "\n    scopes: [orders:read]\n"
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}
	return path
}

func prepareEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AEGIS_CONFIG_PATH",
		"AEGIS_ENV",
		"AEGIS_HTTP_ADDR",
		"AEGIS_READ_TIMEOUT",
		"AEGIS_WRITE_TIMEOUT",
		"AEGIS_IDLE_TIMEOUT",
		"AEGIS_SHUTDOWN_TIMEOUT",
		"AEGIS_UPSTREAM_URL",
		"AEGIS_REDIS_USERNAME",
		"AEGIS_REDIS_PASSWORD",
	} {
		unsetEnv(t, key)
	}
}

func rateLimitedConfig(redisConfiguration, rateLimitConfiguration string) string {
	return redisConfiguration + "routes:\n" +
		"  - id: users\n" +
		"    path_prefix: /api/users\n" +
		"    upstream: http://localhost:8081\n" +
		"    timeout: 5s\n" +
		"    auth:\n" +
		"      mode: public\n" +
		rateLimitConfiguration
}

func validRedisYAML() string {
	return "redis:\n  address: redis:6379\n  connect_timeout: 2s\n  command_timeout: 500ms\n"
}

func validRateLimitYAML() string {
	return "    rate_limit:\n      capacity: 20\n      refill_per_second: 5\n      on_redis_error: deny\n"
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	previous, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	})
}
