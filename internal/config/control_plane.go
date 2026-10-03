package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"
)

var instanceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ControlPlaneHeartbeatInterval is the authority's outbound heartbeat cadence.
const ControlPlaneHeartbeatInterval = 30 * time.Second

type ControlPlaneConfig struct {
	Address, InstanceID, StartupPolicy, StalePolicy string
	InitialSyncTimeout, StaleAfter, DialTimeout     time.Duration
	ReconnectMinBackoff, ReconnectMaxBackoff        time.Duration
	MaxReceiveBytes, AckQueueCapacity               int
	ShutdownTimeout                                 time.Duration
	TLS                                             ControlPlaneTLS
}

type ControlPlaneTLS struct {
	Enabled                                             bool
	ServerName, CAFile, CertificateFile, PrivateKeyFile string
}

type fileControlPlane struct {
	Enabled             bool                `yaml:"enabled"`
	Address             string              `yaml:"address"`
	InstanceID          string              `yaml:"instance_id"`
	StartupPolicy       string              `yaml:"startup_policy"`
	StalePolicy         string              `yaml:"stale_policy"`
	InitialSyncTimeout  string              `yaml:"initial_sync_timeout"`
	StaleAfter          string              `yaml:"stale_after"`
	DialTimeout         string              `yaml:"dial_timeout"`
	ReconnectMinBackoff string              `yaml:"reconnect_min_backoff"`
	ReconnectMaxBackoff string              `yaml:"reconnect_max_backoff"`
	MaxReceiveBytes     int                 `yaml:"max_receive_bytes"`
	AckQueueCapacity    int                 `yaml:"ack_queue_capacity"`
	ShutdownTimeout     string              `yaml:"shutdown_timeout"`
	TLS                 fileControlPlaneTLS `yaml:"tls"`
}

type fileControlPlaneTLS struct {
	Enabled         bool   `yaml:"enabled"`
	ServerName      string `yaml:"server_name"`
	CAFile          string `yaml:"ca_file"`
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile  string `yaml:"private_key_file"`
}

func parseControlPlane(raw fileControlPlane, environment string) (*ControlPlaneConfig, error) {
	if !raw.Enabled {
		return nil, errors.New("control_plane.enabled must be true when section is present")
	}
	if _, _, err := net.SplitHostPort(raw.Address); err != nil {
		return nil, errors.New("control_plane.address must be host:port")
	}
	if !instanceIDPattern.MatchString(raw.InstanceID) {
		return nil, errors.New("control_plane.instance_id must be 1-64 safe ASCII characters")
	}
	if raw.StartupPolicy != "require_remote" && raw.StartupPolicy != "use_bootstrap" {
		return nil, errors.New("control_plane.startup_policy must be require_remote or use_bootstrap")
	}
	if raw.StalePolicy != "serve" && raw.StalePolicy != "deny" {
		return nil, errors.New("control_plane.stale_policy must be serve or deny")
	}
	if environment == "production" && !raw.TLS.Enabled {
		return nil, errors.New("control_plane.tls is required in production")
	}
	if raw.TLS.Enabled {
		if raw.TLS.ServerName == "" || raw.TLS.CAFile == "" || raw.TLS.CertificateFile == "" || raw.TLS.PrivateKeyFile == "" {
			return nil, errors.New("control_plane.tls requires server_name, ca_file, certificate_file, and private_key_file")
		}
	} else if raw.TLS.ServerName != "" || raw.TLS.CAFile != "" || raw.TLS.CertificateFile != "" || raw.TLS.PrivateKeyFile != "" {
		return nil, errors.New("control_plane.tls fields require tls.enabled")
	}
	c := &ControlPlaneConfig{Address: raw.Address, InstanceID: raw.InstanceID, StartupPolicy: raw.StartupPolicy, StalePolicy: raw.StalePolicy,
		MaxReceiveBytes: raw.MaxReceiveBytes, AckQueueCapacity: raw.AckQueueCapacity,
		TLS: ControlPlaneTLS{Enabled: raw.TLS.Enabled, ServerName: raw.TLS.ServerName, CAFile: raw.TLS.CAFile, CertificateFile: raw.TLS.CertificateFile, PrivateKeyFile: raw.TLS.PrivateKeyFile}}
	var err error
	for _, item := range []struct {
		name, raw string
		target    *time.Duration
	}{
		{"initial_sync_timeout", raw.InitialSyncTimeout, &c.InitialSyncTimeout}, {"stale_after", raw.StaleAfter, &c.StaleAfter},
		{"dial_timeout", raw.DialTimeout, &c.DialTimeout}, {"reconnect_min_backoff", raw.ReconnectMinBackoff, &c.ReconnectMinBackoff},
		{"reconnect_max_backoff", raw.ReconnectMaxBackoff, &c.ReconnectMaxBackoff}, {"shutdown_timeout", raw.ShutdownTimeout, &c.ShutdownTimeout},
	} {
		*item.target, err = requiredDuration("control_plane."+item.name, item.raw)
		if err != nil {
			return nil, err
		}
		if *item.target > 10*time.Minute {
			return nil, fmt.Errorf("control_plane.%s must not exceed 10m", item.name)
		}
	}
	if c.ReconnectMaxBackoff < c.ReconnectMinBackoff {
		return nil, errors.New("control_plane.reconnect_max_backoff must be >= reconnect_min_backoff")
	}
	if c.StaleAfter < 2*ControlPlaneHeartbeatInterval {
		return nil, errors.New("control_plane.stale_after must be at least twice the 30s heartbeat interval (1m)")
	}
	if c.MaxReceiveBytes < 1024 || c.MaxReceiveBytes > 2<<20 {
		return nil, errors.New("control_plane.max_receive_bytes must be between 1024 and 2097152")
	}
	if c.AckQueueCapacity < 1 || c.AckQueueCapacity > 64 {
		return nil, errors.New("control_plane.ack_queue_capacity must be between 1 and 64")
	}
	return c, nil
}
