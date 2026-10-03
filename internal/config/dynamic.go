package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"go.yaml.in/yaml/v3"
)

// Dynamic contains only policy and routing data suitable for distribution.
type Dynamic struct {
	APIKeys []auth.Key
	Routes  []router.Route
}

var dynamicRouteIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func Bootstrap(cfg Config) Dynamic {
	return Dynamic{APIKeys: append([]auth.Key(nil), cfg.APIKeys...), Routes: append([]router.Route(nil), cfg.Routes...)}
}

func ReadDynamic(path string) (Dynamic, error) {
	f, err := os.Open(path)
	if err != nil {
		return Dynamic{}, fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Dynamic{}, fmt.Errorf("read snapshot: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Dynamic{}, errors.New("snapshot exceeds 1 MiB")
	}
	var raw struct {
		APIKeys []fileAPIKey `yaml:"api_keys"`
		Routes  []fileRoute  `yaml:"routes"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Dynamic{}, fmt.Errorf("decode snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Dynamic{}, errors.New("snapshot must contain exactly one YAML document")
		}
		return Dynamic{}, fmt.Errorf("decode snapshot: %w", err)
	}
	d := Dynamic{APIKeys: make([]auth.Key, 0, len(raw.APIKeys)), Routes: make([]router.Route, 0, len(raw.Routes))}
	for i, k := range raw.APIKeys {
		key, err := auth.NewKey(k.ID, k.SHA256, k.Scopes)
		if err != nil {
			return Dynamic{}, fmt.Errorf("api_keys[%d]: %w", i, err)
		}
		d.APIKeys = append(d.APIKeys, key)
	}
	for i, r := range raw.Routes {
		route, err := parseRoute(i, r)
		if err != nil {
			return Dynamic{}, err
		}
		d.Routes = append(d.Routes, route)
	}
	if err := ValidateDynamic(d); err != nil {
		return Dynamic{}, err
	}
	return d, nil
}

func ValidateDynamic(d Dynamic) error {
	if len(d.Routes) == 0 || len(d.Routes) > 64 {
		return errors.New("snapshot routes must contain 1-64 entries")
	}
	if len(d.APIKeys) > 256 {
		return errors.New("snapshot api_keys exceeds 256 entries")
	}
	if _, err := auth.NewRegistry(d.APIKeys); err != nil {
		return fmt.Errorf("API key registry: %w", err)
	}
	if _, err := router.New(d.Routes); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	for _, route := range d.Routes {
		if !dynamicRouteIDPattern.MatchString(route.ID) {
			return errors.New("snapshot route ID must be 1-64 safe ASCII characters")
		}
		if route.PathPrefix == "/healthz" || route.PathPrefix == "/readyz" {
			return errors.New("snapshot route shadows gateway health or readiness endpoint")
		}
		if route.Timeout <= 0 || route.Timeout > time.Minute {
			return errors.New("snapshot route timeout is invalid")
		}
		if route.Auth.RequiresAPIKey() {
			if !hasAuthorizedClient(d.APIKeys, route.Auth.RequiredScopes()) {
				return errors.New("route requires scopes not supplied together by any API client")
			}
		}
		if _, err := parseRoute(0, fileRoute{ID: route.ID, PathPrefix: route.PathPrefix, Upstream: route.Upstream, Timeout: route.Timeout.String(), Auth: fileAuth{Mode: string(route.Auth.Mode()), RequiredScopes: route.Auth.RequiredScopes()}}); err != nil {
			return errors.New("snapshot route URL or policy is invalid")
		}
	}
	return nil
}

func hasAuthorizedClient(keys []auth.Key, required []string) bool {
	for _, key := range keys {
		available := make(map[string]struct{}, len(key.Scopes()))
		for _, scope := range key.Scopes() {
			available[scope] = struct{}{}
		}
		all := true
		for _, scope := range required {
			if _, ok := available[scope]; !ok {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
