package pcscf

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// writeCert writes a self-signed certificate for publicHost to files and
// returns their paths and a client configuration that trusts it.
func writeCert(t *testing.T) (certFile, keyFile string, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: publicHost},
		DNSNames:     []string{publicHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, &tls.Config{RootCAs: pool, ServerName: publicHost, MinVersion: tls.VersionTLS12}
}

func TestTheClientListenerTerminatesTLSWithTheCertificateFiles(t *testing.T) {
	cfg := testConfig()
	cfg.ClientTransport, cfg.PublicPort = ClientTLS, 5061
	var client *tls.Config
	cfg.TLSCertFile, cfg.TLSKeyFile, client = writeCert(t)
	s := start(t, cfg, deps{})
	nc, err := tls.Dial("tcp", s.client.String(), client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	p := &peer{t: t, nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{})}
	if res := p.request("sips:" + publicHost + ";lr"); res.StatusCode != 403 {
		t.Fatalf("OPTIONS over TLS answered %d", res.StatusCode)
	}
}

func TestAMissingCertificateStopsTheStart(t *testing.T) {
	cfg := testConfig()
	cfg.ClientTransport = ClientTLS
	cfg.TLSCertFile, cfg.TLSKeyFile = filepath.Join(t.TempDir(), "none.pem"), filepath.Join(t.TempDir(), "none.key")
	err := run(context.Background(), runtimetest.New(t, "pcscf").Runtime, cfg, deps{})
	if err == nil || !strings.Contains(err.Error(), "pcscf: client certificate") {
		t.Fatalf("run = %v", err)
	}
}

func TestAListenerThatCannotBindStopsTheStart(t *testing.T) {
	for _, tt := range []struct{ name, field, want string }{
		{"core", "core", "pcscf: core listener"},
		{"client", "client", "pcscf: client listener"},
		{"client UDP", "udp", "pcscf: client UDP listener"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			switch tt.field {
			case "core":
				cfg.CoreAddr = "192.0.2.1:0"
			case "client":
				cfg.ClientAddr = "192.0.2.1:0"
			case "udp":
				cfg.ClientUDPAddr = "192.0.2.1:0"
			}
			err := run(context.Background(), runtimetest.New(t, "pcscf").Runtime, cfg, deps{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run = %v, want %q", err, tt.want)
			}
		})
	}
}
