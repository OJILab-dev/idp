package transport_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestParsePrivateKeyAcceptsECDSAP384(t *testing.T) {
	key := testpki.NewECDSAKey(t, elliptic.P384())
	sec1DER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, keyPEM := range map[string][]byte{
		"PKCS #8": testpki.EncodePKCS8(t, key),
		"SEC 1":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER}),
	} {
		got, err := transport.ParsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.Equal(key) {
			t.Fatalf("%s: a different key was parsed", name)
		}
	}
}

func TestParsePrivateKeyRejectsOtherKeys(t *testing.T) {
	publicDER, err := x509.MarshalPKIXPublicKey(&testpki.NewECDSAKey(t, elliptic.P384()).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// P-256 was the managed CA fallback; it cannot sign ecdsa-p384-sha384.
	for name, keyPEM := range map[string][]byte{
		"P-256":      testpki.EncodePKCS8(t, testpki.NewECDSAKey(t, elliptic.P256())),
		"Ed25519":    testpki.EncodePKCS8(t, testpki.NewEd25519Key(t)),
		"not PEM":    []byte("not a key"),
		"public key": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
	} {
		if _, err := transport.ParsePrivateKey(keyPEM); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParsePrivateKeyErrorNeverEchoesTheKey(t *testing.T) {
	keyPEM := testpki.EncodePKCS8(t, testpki.NewECDSAKey(t, elliptic.P384()))
	broken := bytes.Replace(keyPEM, []byte("PRIVATE KEY-----\n"), []byte("PRIVATE KEY-----\nAAAA"), 1)
	_, err := transport.ParsePrivateKey(broken)
	if err == nil {
		t.Fatal("broken key accepted")
	}
	body := strings.Split(string(keyPEM), "\n")[1]
	if strings.Contains(err.Error(), body) {
		t.Fatalf("error leaks key material: %v", err)
	}
}

func TestNewHTTPClientVerifiesTheServerAndPresentsNoCertificate(t *testing.T) {
	server := testpki.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 0 {
			t.Error("a client certificate was presented")
		}
	}))
	trusted := transport.NewHTTPClient(transport.Config{RootCAs: testpki.RootCAs(server)})
	resp, err := trusted.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	untrusted := transport.NewHTTPClient(transport.Config{})
	if resp, err := untrusted.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("server with an untrusted certificate accepted")
	}
}

func TestNewHTTPClientRefusesTLS11(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS11, MinVersion: tls.VersionTLS10}
	server.StartTLS()
	defer server.Close()
	client := transport.NewHTTPClient(transport.Config{RootCAs: testpki.RootCAs(server)})
	if resp, err := client.Get(server.URL); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.1 accepted")
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	server := testpki.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	client := transport.NewHTTPClient(transport.Config{RootCAs: testpki.RootCAs(server)})
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || followed.Load() {
		t.Fatalf("redirect followed: status %d", resp.StatusCode)
	}
}

// flakyDoer fails the first failures calls with a transport error and then
// answers with status and header, recording each call's Idempotency-Key.
type flakyDoer struct {
	failures int
	status   int
	header   http.Header
	calls    int
	keys     []string
}

func (d *flakyDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.keys = append(d.keys, req.Header.Get("Idempotency-Key"))
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

func TestRetryingDoerCapsTheDoublingBackoff(t *testing.T) {
	inner := &flakyDoer{failures: 10}
	var waits []time.Duration
	doer := &transport.RetryingDoer{
		Doer: inner, Retries: 5, Backoff: 10 * time.Second, MaxBackoff: 30 * time.Second, Logger: discardLogger(),
		After: func(d time.Duration) <-chan time.Time {
			waits = append(waits, d)
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch
		},
	}
	if _, err := doer.Do(newPost(t)); err == nil {
		t.Fatal("error swallowed")
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
}

func TestRetryingDoerDefaultsTheBackoffCapTo30Seconds(t *testing.T) {
	inner := &flakyDoer{failures: 10}
	var last time.Duration
	doer := &transport.RetryingDoer{
		Doer: inner, Retries: 8, Backoff: time.Second, Logger: discardLogger(),
		After: func(d time.Duration) <-chan time.Time {
			last = d
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch
		},
	}
	_, _ = doer.Do(newPost(t))
	if last != transport.DefaultMaxBackoff {
		t.Fatalf("last wait %v, cap %v", last, transport.DefaultMaxBackoff)
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
