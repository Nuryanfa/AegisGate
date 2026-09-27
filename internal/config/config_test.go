package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range []string{
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

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ReadTimeout != 10*time.Second {
		t.Fatalf("ReadTimeout = %s, want 10s", cfg.ReadTimeout)
	}
	if got := cfg.UpstreamURL.String(); got != "http://localhost:8081" {
		t.Fatalf("UpstreamURL = %q, want %q", got, "http://localhost:8081")
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

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("AEGIS_READ_TIMEOUT", "not-a-duration")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid duration error")
	}
}

func TestLoadRejectsUnsafeUpstream(t *testing.T) {
	t.Setenv("AEGIS_UPSTREAM_URL", "file:///tmp/backend.sock")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid upstream error")
	}
}
