// Package testpki builds throwaway admin keys and HTTPS test servers in memory
// for idpctl's tests. Nothing here touches a real key: every key is generated
// per test and discarded with the process, which is the only kind of key the
// repository's rules let tests create outside the reviewed generation scripts.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// NewECDSAKey generates a throwaway ECDSA key on curve, failing the test on
// error.
//
// Example:
//
//	key := testpki.NewECDSAKey(t, elliptic.P384())
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
//
// Example:
//
//	key := testpki.NewEd25519Key(t)
func NewEd25519Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// EncodePKCS8 returns key as a PKCS #8 "PRIVATE KEY" PEM, the form
// scripts/generate-admin-key.sh stores and idpctl reads from stdin.
//
// Example:
//
//	keyPEM := testpki.EncodePKCS8(t, testpki.NewECDSAKey(t, elliptic.P384()))
func EncodePKCS8(t testing.TB, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// NewTLSServer starts an httptest HTTPS server that accepts TLS 1.2 or later
// and asks for no client certificate, like the admin Worker's host: the
// admin is authenticated by the request signature, not by TLS. The server is
// closed when the test ends. Clients trust it through RootCAs.
//
// Example:
//
//	server := testpki.NewTLSServer(t, handler)
//	client := transport.NewHTTPClient(transport.Config{RootCAs: testpki.RootCAs(server)})
func NewTLSServer(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// RootCAs returns a pool that trusts only server's certificate, so tests keep
// server verification on instead of skipping it.
//
// Example:
//
//	roots := testpki.RootCAs(server)
func RootCAs(server *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}
