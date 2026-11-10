package transport_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

// signatureHeader matches the Signature value idpctl sends: the fixed label and one byte sequence.
var signatureHeader = regexp.MustCompile(`^sig1=:([A-Za-z0-9+/=]+):$`)

// verifySignature checks the Signature header of req over base with key, the way the admin Worker does: the
// value must be exactly 96 bytes, r || s, over SHA-384 of the signature base.
func verifySignature(t *testing.T, key *ecdsa.PublicKey, header, base string) {
	t.Helper()
	m := signatureHeader.FindStringSubmatch(header)
	if m == nil {
		t.Fatalf("Signature %q is not sig1=:<base64>:", header)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(m[1])
	if err != nil || len(raw) != 96 {
		t.Fatalf("signature is %d bytes (err %v), want 96", len(raw), err)
	}
	digest := sha512.Sum384([]byte(base))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(raw[:48]), new(big.Int).SetBytes(raw[48:])) {
		t.Fatal("the signature does not verify over the expected base")
	}
}

// vectorRequest builds the request a vector describes, keeping its header order.
func vectorRequest(t *testing.T, r signedRequest) *http.Request {
	t.Helper()
	var body io.Reader
	if r.BodyUTF8 != "" {
		body = strings.NewReader(r.BodyUTF8)
	}
	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range r.Headers {
		req.Header.Add(h[0], h[1])
	}
	return req
}

func keyidOf(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// fixedSigner returns a signer for a fresh test key whose clock and nonce source are pinned.
func fixedSigner(t *testing.T, created int64, nonces ...string) (*transport.Signer, *ecdsa.PrivateKey) {
	t.Helper()
	key := testpki.NewECDSAKey(t, elliptic.P384())
	signer, err := transport.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	var random bytes.Buffer
	for _, n := range nonces {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(n)
		if err != nil {
			t.Fatal(err)
		}
		random.Write(raw)
	}
	signer.Now = func() time.Time { return time.Unix(created, 0) }
	signer.Rand = &random
	return signer, key
}

func TestNewSignerAcceptsOnlyP384(t *testing.T) {
	if _, err := transport.NewSigner(testpki.NewECDSAKey(t, elliptic.P384())); err != nil {
		t.Fatalf("P-384: %v", err)
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P521()} {
		if _, err := transport.NewSigner(testpki.NewECDSAKey(t, curve)); err == nil {
			t.Errorf("%s accepted", curve.Params().Name)
		}
	}
	if _, err := transport.NewSigner(testpki.NewEd25519Key(t)); err == nil {
		t.Error("Ed25519 accepted")
	}
	if _, err := transport.NewSigner(nil); err == nil {
		t.Error("nil key accepted")
	}
}

func TestSignerUsesAFreshNonceAndTheCurrentTime(t *testing.T) {
	signer, err := transport.NewSigner(testpki.NewECDSAKey(t, elliptic.P384()))
	if err != nil {
		t.Fatal(err)
	}
	nonceOf := regexp.MustCompile(`;nonce="([^"]+)"`)
	createdOf := regexp.MustCompile(`;created=(\d+);`)
	seen := map[string]bool{}
	for range 16 {
		req := newPost(t)
		req.Header.Set("Content-Type", "application/json")
		before := time.Now().Unix()
		if err := signer.Sign(req); err != nil {
			t.Fatal(err)
		}
		input := req.Header.Get("Signature-Input")
		nonce := nonceOf.FindStringSubmatch(input)[1]
		if raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce); err != nil || len(raw) != 32 {
			t.Fatalf("nonce %q is not 32 bytes of strict base64url", nonce)
		}
		if seen[nonce] {
			t.Fatal("nonce reused")
		}
		seen[nonce] = true
		created, _ := strconv.ParseInt(createdOf.FindStringSubmatch(input)[1], 10, 64)
		if created < before || created > time.Now().Unix() {
			t.Fatalf("created %d is not the signing time", created)
		}
	}
}

func TestSignatureBaseNormalizesTheAuthority(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "HTTPS://Admin.Example.com:443/v1/users?limit=50", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", sha256ContentDigest(""))
	_, base, err := transport.SignatureBase(req, transport.SignatureParams{Created: 1, Nonce: "n", Keyid: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(base, "\"@target-uri\": https://admin.example.com/v1/users?limit=50\n") ||
		!strings.Contains(base, "\"@authority\": admin.example.com\n") {
		t.Fatalf("authority not normalized:\n%s", base)
	}

	// A non-default port is part of the authority.
	req, _ = http.NewRequest(http.MethodGet, "https://127.0.0.1:8443/v1/users", nil)
	req.Header.Set("Content-Digest", sha256ContentDigest(""))
	if _, base, _ = transport.SignatureBase(req, transport.SignatureParams{Created: 1, Nonce: "n", Keyid: "k"}); !strings.Contains(base, "\"@authority\": 127.0.0.1:8443\n") {
		t.Fatalf("port dropped:\n%s", base)
	}
}

func TestSignatureBaseRefusesRequestsOutsideTheProfile(t *testing.T) {
	params := transport.SignatureParams{Created: 1, Nonce: "n", Keyid: "k"}
	cases := map[string]func() *http.Request{
		"no Content-Digest": func() *http.Request {
			req, _ := http.NewRequest(http.MethodGet, "https://admin.example.com/v1/users", nil)
			return req
		},
		"POST without Content-Type": func() *http.Request {
			req, _ := http.NewRequest(http.MethodPost, "https://admin.example.com/v1/users", strings.NewReader("{}"))
			req.Header.Set("Content-Digest", sha256ContentDigest("{}"))
			return req
		},
		"repeated Idempotency-Key": func() *http.Request {
			req, _ := http.NewRequest(http.MethodDelete, "https://admin.example.com/v1/users/x", nil)
			req.Header.Set("Content-Digest", sha256ContentDigest(""))
			req.Header.Add("Idempotency-Key", "a")
			req.Header.Add("Idempotency-Key", "b")
			return req
		},
		"GET with a body": func() *http.Request {
			req, _ := http.NewRequest(http.MethodGet, "https://admin.example.com/v1/users", strings.NewReader("{}"))
			req.Header.Set("Content-Digest", sha256ContentDigest("{}"))
			req.Header.Set("Content-Type", "application/json")
			return req
		},
		"unsupported method": func() *http.Request {
			req, _ := http.NewRequest(http.MethodPatch, "https://admin.example.com/v1/users/x", nil)
			req.Header.Set("Content-Digest", sha256ContentDigest(""))
			return req
		},
		"fragment": func() *http.Request {
			req, _ := http.NewRequest(http.MethodGet, "https://admin.example.com/v1/users#x", nil)
			req.Header.Set("Content-Digest", sha256ContentDigest(""))
			return req
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := transport.SignatureBase(build(), params); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSigningDoerResignsEveryAttemptAndSetsTheUserAgent(t *testing.T) {
	key := testpki.NewECDSAKey(t, elliptic.P384())
	signer, err := transport.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tick := int64(1767225600)
	signer.Now = func() time.Time { tick++; return time.Unix(tick, 0) }

	inner := &recordingDoer{failures: 2}
	doer := &transport.RetryingDoer{
		Doer:    &transport.SigningDoer{Doer: inner, Signer: signer, UserAgent: "idpctl/test"},
		Retries: 2, Backoff: time.Millisecond, Logger: discardLogger(),
	}
	original := newPost(t)
	original.Header.Set("Content-Type", "application/json")
	resp, err := doer.Do(original)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(inner.requests) != 3 {
		t.Fatalf("%d attempts, want 3", len(inner.requests))
	}
	inputs := map[string]bool{}
	for i, r := range inner.requests {
		if r.header.Get("User-Agent") != "idpctl/test" {
			t.Errorf("attempt %d: User-Agent %q", i, r.header.Get("User-Agent"))
		}
		if r.header.Get("Idempotency-Key") != original.Header.Get("Idempotency-Key") || r.body != `{"name":"Alice"}` {
			t.Errorf("attempt %d changed the Idempotency-Key or the body", i)
		}
		input := r.header.Get("Signature-Input")
		if inputs[input] {
			t.Errorf("attempt %d reused a Signature-Input: %s", i, input)
		}
		inputs[input] = true
		verifySignature(t, &key.PublicKey, r.header.Get("Signature"), r.base(t))
	}
	if original.Header.Get("Signature") != "" || original.Header.Get("User-Agent") != "" {
		t.Error("the caller's request was modified")
	}
}

func TestSigningDoerSendsNothingWhenSigningFails(t *testing.T) {
	signer, err := transport.NewSigner(testpki.NewECDSAKey(t, elliptic.P384()))
	if err != nil {
		t.Fatal(err)
	}
	inner := &recordingDoer{}
	doer := &transport.SigningDoer{Doer: inner, Signer: signer, UserAgent: "idpctl/test"}
	// No Content-Type on a POST is outside the profile.
	if _, err := doer.Do(newPost(t)); err == nil {
		t.Fatal("unsigned request accepted")
	}
	if len(inner.requests) != 0 {
		t.Fatal("an unsigned request was sent")
	}
}

type recordedAttempt struct {
	method, url string
	header      http.Header
	body        string
}

// base rebuilds the signature base the attempt was signed over, from what was sent.
func (r recordedAttempt) base(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequest(r.method, r.url, strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = r.header.Clone()
	input := r.header.Get("Signature-Input")
	m := regexp.MustCompile(`;created=(\d+);nonce="([^"]+)";keyid="([0-9a-f]+)";`).FindStringSubmatch(input)
	if m == nil {
		t.Fatalf("Signature-Input %q", input)
	}
	created, _ := strconv.ParseInt(m[1], 10, 64)
	got, base, err := transport.SignatureBase(req, transport.SignatureParams{Created: created, Nonce: m[2], Keyid: m[3]})
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("Signature-Input %q does not match the request, want %q", input, got)
	}
	if want := sha256ContentDigest(r.body); r.header.Get("Content-Digest") != want {
		t.Fatalf("Content-Digest %q, want %q", r.header.Get("Content-Digest"), want)
	}
	return base
}

// recordingDoer fails the first failures attempts with a transport error and records every attempt.
type recordingDoer struct {
	failures int
	requests []recordedAttempt
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	d.requests = append(d.requests, recordedAttempt{method: req.Method, url: req.URL.String(), header: req.Header.Clone(), body: string(body)})
	if len(d.requests) <= d.failures {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
}
