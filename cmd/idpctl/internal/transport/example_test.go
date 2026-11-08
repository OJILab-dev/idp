package transport_test

import (
	"crypto/elliptic"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

// ExampleLoadClientCertificate pairs a certificate with its ECDSA key and
// rejects a key type the design excludes.
func ExampleLoadClientCertificate() {
	t := &testing.T{}
	ca := testpki.NewCA(t)

	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	_, err := transport.LoadClientCertificate(certPEM, keyPEM)
	fmt.Println(err)

	certPEM, keyPEM = ca.IssueClient(t, testpki.NewEd25519Key(t))
	_, err = transport.LoadClientCertificate(certPEM, keyPEM)
	fmt.Println(err)
	// Output:
	// <nil>
	// the admin key must be ECDSA, got ed25519.PublicKey
}

// ExampleNewHTTPClient calls an mTLS server with the admin certificate.
func ExampleNewHTTPClient() {
	t := &testing.T{}
	ca := testpki.NewCA(t)
	server := ca.NewMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	cert, _ := transport.LoadClientCertificate(certPEM, keyPEM)

	client := transport.NewHTTPClient(transport.Config{Certificate: cert, RootCAs: testpki.RootCAs(server)})
	resp, err := client.Get(server.URL)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp.Body.Close()
	fmt.Println(resp.StatusCode)
	// Output: 204
}

// ExampleNewIdempotencyKey creates the key for one invocation.
func ExampleNewIdempotencyKey() {
	key, _ := transport.NewIdempotencyKey()
	fmt.Println(len(key))
	// Output: 43
}

// ExampleRetryingDoer retries a lost response with the same request, so the
// Idempotency-Key and body are unchanged.
func ExampleRetryingDoer() {
	inner := &flakyDoer{failures: 1}
	doer := &transport.RetryingDoer{Doer: inner, Retries: 2, Backoff: time.Millisecond, Logger: discardLogger()}
	resp, err := doer.Do(newPost(&testing.T{}))
	if err != nil {
		fmt.Println(err)
		return
	}
	resp.Body.Close()
	fmt.Println(inner.calls, inner.keys[0] == inner.keys[1])
	// Output: 2 true
}
