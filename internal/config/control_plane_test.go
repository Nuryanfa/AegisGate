package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nuryanfa/AegisGate/internal/auth"
)

func TestControlPlaneOmittedPreservesExistingConfiguration(t *testing.T) {
	prepareEnvironment(t)
	path := filepath.Join("..", "..", "configs", "config.example.yaml")
	t.Setenv("AEGIS_CONFIG_PATH", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlane != nil {
		t.Fatal("control plane enabled by default")
	}
}

func TestControlPlaneExampleAndProductionTLSGuard(t *testing.T) {
	prepareEnvironment(t)
	path := filepath.Join("..", "..", "configs", "config.control-plane-demo.yaml")
	t.Setenv("AEGIS_CONFIG_PATH", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlane == nil || cfg.ControlPlane.InstanceID != "gateway-demo" {
		t.Fatal("control-plane settings missing")
	}
	t.Setenv("AEGIS_CONTROL_PLANE_INSTANCE_ID", "gateway-a")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlane.InstanceID != "gateway-a" {
		t.Fatal("instance ID override ignored")
	}
	t.Setenv("AEGIS_ENV", "production")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("insecure production accepted: %v", err)
	}
}

func TestDynamicExampleAndMalformedPolicy(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "snapshots", "example.yaml")
	d, err := ReadDynamic(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Routes) != 2 || len(d.APIKeys) != 1 {
		t.Fatal("example snapshot incomplete")
	}
	if err := ValidateDynamic(Dynamic{Routes: d.Routes}); err == nil {
		t.Fatal("missing API scope accepted")
	}
	a, _ := auth.NewKey("first", strings.Repeat("0", 64), []string{"one"})
	b, _ := auth.NewKey("second", strings.Repeat("1", 64), []string{"two"})
	policy, _ := auth.NewPolicy("api_key", []string{"one", "two"})
	d.APIKeys = []auth.Key{a, b}
	d.Routes[1].Auth = policy
	if err := ValidateDynamic(d); err == nil {
		t.Fatal("route with scopes split across clients accepted")
	}
}
