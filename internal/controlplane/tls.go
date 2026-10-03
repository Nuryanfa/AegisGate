package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/config"
	"google.golang.org/grpc/credentials"
)

func ServerCredentials(options ServerTLS) (credentials.TransportCredentials, error) {
	if !options.Enabled {
		return nil, errors.New("server TLS is disabled")
	}
	certificate, err := tls.LoadX509KeyPair(options.CertificateFile, options.PrivateKeyFile)
	if err != nil {
		return nil, errors.New("load server certificate or key failed")
	}
	if err := validateLeaf(certificate); err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(options.ClientCAFile)
	if err != nil {
		return nil, errors.New("read client CA failed")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("client CA is invalid")
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}), nil
}

func ClientCredentials(options config.ControlPlaneTLS) (credentials.TransportCredentials, error) {
	if !options.Enabled {
		return nil, errors.New("client TLS is disabled")
	}
	certificate, err := tls.LoadX509KeyPair(options.CertificateFile, options.PrivateKeyFile)
	if err != nil {
		return nil, errors.New("load client certificate or key failed")
	}
	if err := validateLeaf(certificate); err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(options.CAFile)
	if err != nil {
		return nil, errors.New("read server CA failed")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("server CA is invalid")
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, RootCAs: pool, ServerName: options.ServerName}), nil
}

func validateLeaf(pair tls.Certificate) error {
	if len(pair.Certificate) == 0 {
		return errors.New("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("TLS certificate is malformed")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("TLS certificate is not currently valid")
	}
	return nil
}
