package transport_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadClientCertificateAcceptsECDSAP384AndP256(t *testing.T) {
	ca := testpki.NewCA(t)
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P256()} {
		certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, curve))
		if _, err := transport.LoadClientCertificate(certPEM, keyPEM); err != nil {
			t.Errorf("%s: %v", curve.Params().Name, err)
		}
	}
}

func TestLoadClientCertificateRejectsOtherKeys(t *testing.T) {
	ca := testpki.NewCA(t)

	certPEM, keyPEM := ca.IssueClient(t, testpki.NewEd25519Key(t))
	if _, err := transport.LoadClientCertificate(certPEM, keyPEM); err == nil {
		t.Error("Ed25519 key accepted")
	}

	certPEM, keyPEM = ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P521()))
	if _, err := transport.LoadClientCertificate(certPEM, keyPEM); err == nil {
		t.Error("P-521 key accepted")
	}

	otherCert, _ := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	if _, err := transport.LoadClientCertificate(otherCert, keyPEM); err == nil {
		t.Error("mismatched certificate and key accepted")
	}

	if _, err := transport.LoadClientCertificate(certPEM, nil); err == nil {
		t.Error("empty key accepted")
	}
}

func TestLoadClientCertificateErrorNeverEchoesTheKey(t *testing.T) {
	ca := testpki.NewCA(t)
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	broken := bytes.Replace(keyPEM, []byte("PRIVATE KEY-----\n"), []byte("PRIVATE KEY-----\nAAAA"), 1)
	_, err := transport.LoadClientCertificate(certPEM, broken)
	if err == nil {
		t.Fatal("broken key accepted")
	}
	body := strings.Split(string(keyPEM), "\n")[1]
	if strings.Contains(err.Error(), body) {
		t.Fatalf("error leaks key material: %v", err)
	}
}

func TestNewHTTPClientPresentsTheCertificateAndVerifiesTheServer(t *testing.T) {
	ca := testpki.NewCA(t)
	server := ca.NewMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("no client certificate")
		}
		if r.TLS.Version < tls.VersionTLS12 {
			t.Errorf("TLS version %x", r.TLS.Version)
		}
	}))
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	cert, err := transport.LoadClientCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	trusted := transport.NewHTTPClient(transport.Config{Certificate: cert, RootCAs: testpki.RootCAs(server)})
	resp, err := trusted.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Without the test server in RootCAs the system roots apply, and the
	// handshake must fail: verification is never skipped.
	untrusted := transport.NewHTTPClient(transport.Config{Certificate: cert})
	if resp, err := untrusted.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("server with an untrusted certificate accepted")
	}
}

func TestNewHTTPClientRefusesTLS11(t *testing.T) {
	ca := testpki.NewCA(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS11, MinVersion: tls.VersionTLS10}
	server.StartTLS()
	defer server.Close()
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	cert, err := transport.LoadClientCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := transport.NewHTTPClient(transport.Config{Certificate: cert, RootCAs: testpki.RootCAs(server)})
	if resp, err := client.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.1 accepted")
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	ca := testpki.NewCA(t)
	var followed atomic.Bool
	server := ca.NewMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	cert, err := transport.LoadClientCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := transport.NewHTTPClient(transport.Config{Certificate: cert, RootCAs: testpki.RootCAs(server)})
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || followed.Load() {
		t.Fatalf("redirect followed: status %d", resp.StatusCode)
	}
}

func TestNewIdempotencyKeyIs32RandomBytesAsBase64URL(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	seen := map[string]bool{}
	for range 64 {
		key, err := transport.NewIdempotencyKey()
		if err != nil {
			t.Fatal(err)
		}
		if !shape.MatchString(key) {
			t.Fatalf("key %q does not match the contract", key)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(key)
		if err != nil || len(raw) != 32 {
			t.Fatalf("key %q is not 32 bytes of strict base64url: %v", key, err)
		}
		if seen[key] {
			t.Fatal("duplicate key")
		}
		seen[key] = true
	}
}

// flakyDoer fails the first failures calls with a transport error and then
// records what reached the "server".
type flakyDoer struct {
	failures int
	status   int
	header   http.Header
	calls    int
	keys     []string
	bodies   []string
}

func (d *flakyDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.keys = append(d.keys, req.Header.Get("Idempotency-Key"))
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		d.bodies = append(d.bodies, string(body))
	}
	if d.calls <= d.failures {
		return nil, errors.New("connection reset by peer")
	}
	status := d.status
	if status == 0 {
		status = http.StatusOK
	}
	header := d.header
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
}

func newPost(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://admin.example/v1/users", bytes.NewReader([]byte(`{"name":"Alice"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Idempotency-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	return req
}

func TestRetryingDoerReusesTheIdempotencyKeyAndBody(t *testing.T) {
	inner := &flakyDoer{failures: 2}
	doer := &transport.RetryingDoer{Doer: inner, Retries: 2, Backoff: time.Millisecond, Logger: discardLogger()}
	resp, err := doer.Do(newPost(t))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if inner.calls != 3 {
		t.Fatalf("calls = %d, want 3", inner.calls)
	}
	for i := range inner.calls {
		if inner.keys[i] != inner.keys[0] || inner.bodies[i] != `{"name":"Alice"}` {
			t.Fatalf("attempt %d sent key %q body %q", i, inner.keys[i], inner.bodies[i])
		}
	}
}

func TestRetryingDoerGivesUpAfterRetries(t *testing.T) {
	inner := &flakyDoer{failures: 10}
	doer := &transport.RetryingDoer{Doer: inner, Retries: 2, Backoff: time.Millisecond, Logger: discardLogger()}
	if _, err := doer.Do(newPost(t)); err == nil {
		t.Fatal("error swallowed")
	}
	if inner.calls != 3 {
		t.Fatalf("calls = %d, want 3", inner.calls)
	}
}

func TestRetryingDoerRetriesEdgeUnavailableButNotProblems(t *testing.T) {
	edge := &flakyDoer{status: http.StatusServiceUnavailable, header: http.Header{"Content-Type": {"text/html"}}}
	doer := &transport.RetryingDoer{Doer: edge, Retries: 2, Backoff: time.Millisecond, Logger: discardLogger()}
	resp, err := doer.Do(newPost(t))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if edge.calls != 3 {
		t.Fatalf("edge 503: calls = %d, want 3", edge.calls)
	}

	problem := &flakyDoer{status: http.StatusInternalServerError, header: http.Header{"Content-Type": {"application/problem+json"}}}
	doer = &transport.RetryingDoer{Doer: problem, Retries: 2, Backoff: time.Millisecond, Logger: discardLogger()}
	resp, err = doer.Do(newPost(t))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if problem.calls != 1 {
		t.Fatalf("problem 500: calls = %d, want 1", problem.calls)
	}
}

func TestRetryingDoerStopsWhenTheContextEnds(t *testing.T) {
	inner := &flakyDoer{failures: 10}
	doer := &transport.RetryingDoer{Doer: inner, Retries: 5, Backoff: time.Hour, Logger: discardLogger()}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := doer.Do(newPost(t).WithContext(ctx)); err == nil {
		t.Fatal("error swallowed")
	}
	if inner.calls != 1 {
		t.Fatalf("calls = %d, want 1", inner.calls)
	}
}
