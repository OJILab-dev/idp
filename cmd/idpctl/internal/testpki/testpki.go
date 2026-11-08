// Package testpki builds throwaway certificate authorities, client
// certificates, and mTLS test servers in memory for idpctl's tests. Nothing
// here touches a real key: every key is generated per test and discarded with
// the process, which is the only kind of key the repository's rules let tests
// create outside the reviewed generation scripts.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// CA is an in-memory certificate authority that issues client certificates
// and is the only issuer an mTLS test server accepts.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// NewCA creates a self-signed ECDSA P-384 CA valid for one hour. It fails the
// test on any error, so callers never handle partial PKI state.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key := NewECDSAKey(t, elliptic.P384())
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idpctl test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{cert: cert, key: key}
}

// NewECDSAKey generates a throwaway ECDSA key on curve, failing the test on
// error.
func NewECDSAKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// NewEd25519Key generates a throwaway Ed25519 key, used to check that idpctl
// refuses key types the design excludes.
func NewEd25519Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// IssueClient signs a client-authentication certificate for key and returns
// the certificate and the PKCS #8 private key as PEM, the shapes idpctl reads
// from --cert and stdin.
func (ca *CA) IssueClient(t testing.TB, key crypto.Signer) (certPEM, keyPEM []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "idpctl test admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return certPEM, keyPEM
}

// NewMTLSServer starts an httptest TLS server that requires a client
// certificate issued by ca, mirroring the edge mTLS in front of the admin
// Worker. The server is closed when the test ends. Clients trust it through
// RootCAs.
func (ca *CA) NewMTLSServer(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// RootCAs returns a pool that trusts only server's certificate, so tests keep
// server verification on instead of skipping it.
func RootCAs(server *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}
