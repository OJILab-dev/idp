// Package transport builds the HTTPS client idpctl uses to reach the admin
// API: mTLS with the admin's ECDSA certificate, server verification always on,
// no redirects, and retries that resend the same request, so a retried write
// carries the same Idempotency-Key and the admin Worker applies it at most
// once.
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"
)

// Config describes the client side of the admin API connection.
type Config struct {
	// Certificate is the admin's client certificate and private key.
	Certificate tls.Certificate
	// RootCAs overrides the system roots. Only tests set it; production
	// verifies the admin host against the system roots.
	RootCAs *x509.CertPool
	// Timeout bounds each attempt. Zero means 30 seconds.
	Timeout time.Duration
}

// LoadClientCertificate pairs the certificate PEM with the private key PEM
// and accepts only ECDSA P-384 or P-256 keys, the curves idpctl.md allows for
// the admin key (P-256 only as the fallback if the managed CA rejects P-384).
// Errors never include the key bytes.
func LoadClientCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// tls.X509KeyPair errors describe the PEM structure, not its
		// content, but the message is rebuilt anyway so a future change in
		// the standard library cannot start echoing key material.
		return tls.Certificate{}, errors.New("the certificate and the private key from stdin do not form a valid pair")
	}
	public, ok := pair.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("the admin key must be ECDSA, got %T", pair.Leaf.PublicKey)
	}
	if public.Curve != elliptic.P384() && public.Curve != elliptic.P256() {
		return tls.Certificate{}, fmt.Errorf("the admin key must be on P-384 or P-256, got %s", public.Curve.Params().Name)
	}
	return pair, nil
}

// NewHTTPClient returns an HTTP client that presents cfg.Certificate,
// requires TLS 1.2 or later, verifies the server, and returns redirects as
// responses instead of following them: the admin API never redirects, and
// following one would offer the client certificate to another host.
func NewHTTPClient(cfg Config) *http.Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cfg.Certificate},
				RootCAs:      cfg.RootCAs,
				MinVersion:   tls.VersionTLS12,
			},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewIdempotencyKey returns 32 random bytes as unpadded base64url, the
// Idempotency-Key shape in cross-language-contract.md. idpctl creates one per
// invocation and reuses it only for its own retries.
func NewIdempotencyKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Doer sends one HTTP request; *http.Client satisfies it.
type Doer interface {
	// Do sends req and returns the response, or an error when no response
	// arrived. A non-2xx status is a response, not an error.
	Do(req *http.Request) (*http.Response, error)
}

// RetryingDoer resends a request when no response arrived or when the edge
// answered 502, 503, or 504 without a problem body. Each attempt is the same
// request with the same headers, so writes reuse their Idempotency-Key and
// PUT and DELETE stay idempotent. Problems from the admin Worker, including
// internal, are final: they come from a completed attempt.
type RetryingDoer struct {
	// Doer sends each attempt.
	Doer Doer
	// Retries is the number of attempts after the first.
	Retries int
	// Backoff is the wait before the first retry; it doubles per retry.
	Backoff time.Duration
	// Logger receives one warning per retry.
	Logger *slog.Logger
}

// Do sends req, retrying as described on RetryingDoer. It returns the last
// response or error, and stops early when req's context ends.
func (d *RetryingDoer) Do(req *http.Request) (*http.Response, error) {
	wait := d.Backoff
	for attempt := 0; ; attempt++ {
		current := req
		if attempt > 0 {
			var err error
			if current, err = rewind(req); err != nil {
				return nil, err
			}
		}
		resp, err := d.Doer.Do(current)
		if attempt >= d.Retries || !retryable(resp, err) || req.Context().Err() != nil {
			return resp, err
		}
		reason := "no response"
		if err != nil {
			reason = err.Error()
		} else {
			reason = resp.Status
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		d.Logger.Warn("retrying the admin api request",
			slog.String("method", req.Method),
			slog.String("path", req.URL.Path),
			slog.Int("attempt", attempt+1),
			slog.String("error", reason))
		select {
		case <-req.Context().Done():
			if err != nil {
				return nil, err
			}
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func rewind(req *http.Request) (*http.Request, error) {
	next := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, errors.New("the request body cannot be replayed for a retry")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("replay the request body: %w", err)
		}
		next.Body = body
	}
	return next, nil
}

func retryable(resp *http.Response, err error) bool {
	if err != nil {
		// A per-attempt timeout is worth retrying; the caller's own
		// cancellation is checked separately against the request context.
		return true
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		return media != "application/problem+json"
	}
	return false
}
