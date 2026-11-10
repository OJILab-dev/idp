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

// ExampleNewSigner accepts only a P-384 key and derives the keyid from it.
func ExampleNewSigner() {
	t := &testing.T{}
	signer, err := transport.NewSigner(testpki.NewECDSAKey(t, elliptic.P384()))
	fmt.Println(err, len(signer.Keyid()))

	_, err = transport.NewSigner(testpki.NewECDSAKey(t, elliptic.P256()))
	fmt.Println(err)
	// Output:
	// <nil> 64
	// the admin key must be on P-384, got P-256
}

// ExampleKeyid computes the allowlist keyid of a public key.
func ExampleKeyid() {
	key := testpki.NewECDSAKey(&testing.T{}, elliptic.P384())
	keyid, err := transport.Keyid(&key.PublicKey)
	fmt.Println(err, len(keyid))
	// Output: <nil> 64
}

// ExampleContentDigest is the digest a request without a body carries.
func ExampleContentDigest() {
	fmt.Println(transport.ContentDigest(nil))
	// Output: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
}

// ExampleSignatureBase builds the Signature-Input and the base for fixed
// parameters, as the contract vectors do.
func ExampleSignatureBase() {
	req, _ := http.NewRequest(http.MethodGet, "https://admin.example.com/v1/users?limit=50", nil)
	req.Header.Set("Content-Digest", transport.ContentDigest(nil))
	input, base, err := transport.SignatureBase(req, transport.SignatureParams{Created: 1767225600, Nonce: "n", Keyid: "k"})
	fmt.Println(err)
	fmt.Println(input)
	fmt.Println(base)
	// Output:
	// <nil>
	// sig1=("@method" "@target-uri" "@authority" "content-digest");created=1767225600;nonce="n";keyid="k";tag="idp-admin"
	// "@method": GET
	// "@target-uri": https://admin.example.com/v1/users?limit=50
	// "@authority": admin.example.com
	// "content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
	// "@signature-params": ("@method" "@target-uri" "@authority" "content-digest");created=1767225600;nonce="n";keyid="k";tag="idp-admin"
}

// ExampleSigner_Sign adds Content-Digest, Signature-Input, and Signature.
func ExampleSigner_Sign() {
	signer, _ := transport.NewSigner(testpki.NewECDSAKey(&testing.T{}, elliptic.P384()))
	req, _ := http.NewRequest(http.MethodDelete, "https://admin.example.com/v1/users/x", nil)
	fmt.Println(signer.Sign(req))
	fmt.Println(req.Header.Get("Content-Digest"))
	fmt.Println(len(req.Header.Get("Signature")))
	// Output:
	// <nil>
	// sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
	// 135
}

// ExampleSigningDoer signs each attempt again under RetryingDoer, so a retry
// carries a new nonce.
func ExampleSigningDoer() {
	signer, _ := transport.NewSigner(testpki.NewECDSAKey(&testing.T{}, elliptic.P384()))
	inner := &recordingDoer{failures: 1}
	doer := &transport.RetryingDoer{
		Doer:    &transport.SigningDoer{Doer: inner, Signer: signer, UserAgent: "idpctl/devel"},
		Retries: 1, Backoff: time.Millisecond, Logger: discardLogger(),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://admin.example.com/v1/users", nil)
	resp, err := doer.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp.Body.Close()
	first, second := inner.requests[0].header, inner.requests[1].header
	fmt.Println(first.Get("User-Agent"), first.Get("Signature-Input") != second.Get("Signature-Input"))
	// Output: idpctl/devel true
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
