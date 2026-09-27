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
routes:
  - id: users
    path_prefix: /api/users
    upstream: http://localhost:8081
    timeout: 750ms
  - id: orders
    path_prefix: /api/orders
    upstream: http://localhost:8082/base
    timeout: 2s
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
		{
			name: "duplicate IDs",
			configuration: routesConfig(
				"  - id: duplicate\n    path_prefix: /one\n    upstream: http://one.example\n    timeout: 1s\n" +
					"  - id: duplicate\n    path_prefix: /two\n    upstream: http://two.example\n    timeout: 1s\n"),
			wantError: "duplicate route ID",
		},
		{
			name: "duplicate prefixes",
			configuration: routesConfig(
				"  - id: one\n    path_prefix: /same\n    upstream: http://one.example\n    timeout: 1s\n" +
					"  - id: two\n    path_prefix: /same\n    upstream: http://two.example\n    timeout: 1s\n"),
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

func validConfig() string {
	return singleRoute("users", "/api/users", "http://localhost:8081", "5s")
}

func routesConfig(routes string) string {
	return "routes:\n" + routes
}

func singleRoute(id, prefix, upstream, timeout string) string {
	return routesConfig("  - id: " + id + "\n" +
		"    path_prefix: " + prefix + "\n" +
		"    upstream: " + upstream + "\n" +
		"    timeout: " + timeout + "\n")
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
	} {
		unsetEnv(t, key)
	}
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
