// Package transport builds the HTTPS client idpctl uses to reach the admin
// API: an RFC 9421 signature by the admin's ECDSA P-384 key on every request
// (the only admin authentication, hosting-modes.md 4.2), server verification
// always on, no redirects, and retries that resend the same request,
// re-signed, so a retried write carries the same Idempotency-Key and the
// admin Worker applies it at most once.
package transport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"
)

// Config describes the client side of the admin API connection. It holds no
// client certificate: the admin is authenticated by the request signature.
type Config struct {
	// RootCAs overrides the system roots. Only tests set it; production
	// verifies the admin host against the system roots.
	RootCAs *x509.CertPool
	// Timeout bounds each attempt. Zero means 30 seconds.
	Timeout time.Duration
}

// errUnreadableKey is the one message for a key PEM that does not parse. The
// parsers' own errors describe the structure, not the content, but they are
// replaced anyway so a future change in the standard library cannot start
// echoing key material.
var errUnreadableKey = errors.New("stdin does not hold a PEM private key (PKCS #8 or SEC 1)")

// ParsePrivateKey reads the admin private key PEM that idpctl takes on stdin
// and accepts only an ECDSA P-384 key, the one key type that can make the
// ecdsa-p384-sha384 signatures the admin Worker verifies (hosting-modes.md
// 3.3 and 5.1). It takes the first PEM block whose type ends in
// "PRIVATE KEY" and reads it as PKCS #8 (what scripts/generate-admin-key.sh
// stores) or SEC 1, the encodings idpctl has accepted since plan step 4.
// Errors name the key type or curve, never key material.
//
// Example:
//
//	key, err := transport.ParsePrivateKey(keyPEM)
//	if err != nil {
//		return err
//	}
//	signer, err := transport.NewSigner(key)
func ParsePrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	rest := keyPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errUnreadableKey
		}
		if block.Type != "PRIVATE KEY" && !strings.HasSuffix(block.Type, " PRIVATE KEY") {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, errUnreadableKey
			}
		}
		return adminKey(key)
	}
}

// adminKey returns key as an *ecdsa.PrivateKey on P-384, or an error naming
// what it is instead. ParsePrivateKey and NewSigner share it so the two
// cannot disagree about which keys are admin keys.
func adminKey(key crypto.PrivateKey) (*ecdsa.PrivateKey, error) {
	private, ok := key.(*ecdsa.PrivateKey)
	if !ok || private == nil {
		return nil, fmt.Errorf("the admin key must be ECDSA, got %T", key)
	}
	if private.Curve != elliptic.P384() {
		return nil, fmt.Errorf("the admin key must be on P-384, got %s", private.Curve.Params().Name)
	}
	return private, nil
}

// NewHTTPClient returns an HTTP client that presents no client certificate,
// requires TLS 1.2 or later, verifies the server, and returns redirects as
// responses instead of following them: the admin API never redirects, and
// following one would send a signed request to another URL.
//
// Example:
//
//	client := transport.NewHTTPClient(transport.Config{Timeout: 10 * time.Second})
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
				RootCAs:    cfg.RootCAs,
				MinVersion: tls.VersionTLS12,
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
// PUT and DELETE stay idempotent. Put a SigningDoer under it so each attempt
// is signed again with a new created and nonce. Problems from the admin
// Worker, including internal, are final: they come from a completed attempt.
type RetryingDoer struct {
	// Doer sends each attempt.
	Doer Doer
	// Retries is the number of attempts after the first.
	Retries int
	// Backoff is the wait before the first retry; it doubles per retry up
	// to MaxBackoff.
	Backoff time.Duration
	// MaxBackoff caps the doubled wait. Zero means DefaultMaxBackoff.
	MaxBackoff time.Duration
	// Logger receives one warning per retry.
	Logger *slog.Logger
	// After replaces time.After for the wait between attempts. Tests only:
	// it lets them observe the waits without sleeping.
	After func(time.Duration) <-chan time.Time
}

// DefaultMaxBackoff caps the wait between retries when
// RetryingDoer.MaxBackoff is zero, so a large --retries cannot make one
// invocation hang for hours.
const DefaultMaxBackoff = 30 * time.Second

// Do sends req, retrying as described on RetryingDoer. It returns the last
// response or error, and stops early when req's context ends.
func (d *RetryingDoer) Do(req *http.Request) (*http.Response, error) {
	limit := d.MaxBackoff
	if limit <= 0 {
		limit = DefaultMaxBackoff
	}
	after := d.After
	if after == nil {
		after = time.After
	}
	wait := min(d.Backoff, limit)
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
		case <-after(wait):
		}
		wait = min(wait*2, limit)
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
