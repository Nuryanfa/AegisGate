package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func issueTestCert(t *testing.T, ca testCA, name string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
func writeTestCA(t *testing.T, ca testCA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.pem, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMutualTLSAcceptsOnlyTrustedClientsAndServerName(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	serverCert, serverKey := issueTestCert(t, ca, "aegis-control-plane", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issueTestCert(t, ca, "gateway-a", x509.ExtKeyUsageClientAuth)
	badCert, badKey := issueTestCert(t, other, "gateway-b", x509.ExtKeyUsageClientAuth)
	serverCreds, err := ServerCredentials(ServerTLS{Enabled: true, CertificateFile: serverCert, PrivateKeyFile: serverKey, ClientCAFile: writeTestCA(t, ca)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewServer(testDynamic("http://localhost:8081"), 2, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(serverCreds))
	cpb.RegisterConfigurationServiceServer(server, service)
	go server.Serve(listener)
	defer server.Stop()
	for _, tc := range []struct {
		name, cert, key, serverName string
		wantSuccess                 bool
	}{
		{"valid", clientCert, clientKey, "aegis-control-plane", true},
		{"untrusted-client", badCert, badKey, "aegis-control-plane", false},
		{"wrong-server-name", clientCert, clientKey, "wrong-name", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := ClientCredentials(config.ControlPlaneTLS{Enabled: true, ServerName: tc.serverName, CAFile: writeTestCA(t, ca), CertificateFile: tc.cert, PrivateKeyFile: tc.key})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(creds), grpc.WithBlock())
			if tc.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
			} else if err == nil {
				conn.Close()
				t.Fatal("invalid TLS identity connected")
			}
		})
	}
}
