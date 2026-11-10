package transport

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The fixed parts of the admin signature profile (docs/design/hosting-modes.md 3.2 and 3.12). The admin Worker
// accepts nothing else, so none of them is configurable.
const (
	// SignatureLabel is the one member name of Signature-Input and Signature. The verifier does not interpret
	// it; it is fixed so the header can be compared with the contract vectors character for character.
	SignatureLabel = "sig1"
	// SignatureTag is the tag parameter, which keeps signatures made for another purpose from passing as admin
	// API signatures (RFC 9421 section 7.2.7).
	SignatureTag = "idp-admin"
)

// nonceBytes is the size of the random nonce, the same shape as Idempotency-Key and the IdP's tokens.
const nonceBytes = 32

// maxSignedBodyBytes bounds the body idpctl buffers to digest it. The admin API's bodies are small JSON
// objects, so a larger one is a bug rather than something to sign.
const maxSignedBodyBytes = 1 << 20

// coordinateBytes is the size of r and of s in an ecdsa-p384-sha384 signature (RFC 9421 section 3.3.5).
const coordinateBytes = 48

// SignatureParams are the per-request parameters of the signature: everything in @signature-params except the
// fixed tag.
type SignatureParams struct {
	// Created is the signing time in UNIX seconds.
	Created int64
	// Nonce is the base64url of 32 random bytes, unique per attempt.
	Nonce string
	// Keyid identifies the signing key: the lower-case hex SHA-256 of its SubjectPublicKeyInfo DER.
	Keyid string
}

// Signer signs admin API requests with the admin's ECDSA P-384 key as RFC 9421 describes, in the one shape
// hosting-modes.md 3.2 fixes. It holds the private key only in memory and never prints or logs it.
type Signer struct {
	key   *ecdsa.PrivateKey
	keyid string

	// Now replaces time.Now for created. Tests only: it pins the vectors' created.
	Now func() time.Time
	// Rand replaces crypto/rand as the source of nonces. Tests only: it pins the vectors' nonces. The ECDSA
	// signature itself always draws from crypto/rand.
	Rand io.Reader
}

// NewSigner returns a Signer for key, which must be an *ecdsa.PrivateKey on P-384: the admin Worker decides the
// algorithm from its allowlist and accepts only ecdsa-p384-sha384, so any other key could never be verified.
// The keyid is computed from the key's public half, never taken from the caller, so a hand-written keyid
// cannot disagree with the key. Errors name the key type or curve, never key material.
//
// Example:
//
//	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
//	signer, err := transport.NewSigner(key)
//	if err != nil {
//		return err
//	}
//	fmt.Println(signer.Keyid()) // 64 lower-case hex characters
func NewSigner(key crypto.PrivateKey) (*Signer, error) {
	private, err := adminKey(key)
	if err != nil {
		return nil, err
	}
	keyid, err := Keyid(&private.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: private, keyid: keyid}, nil
}

// Keyid returns the keyid the Signer puts in every signature. It is public: the allowlist row and the audit
// log carry the same value, so an admin can compare them when the admin Worker answers forbidden.
func (s *Signer) Keyid() string {
	return s.keyid
}

// Keyid returns the lower-case hex SHA-256 of key's SubjectPublicKeyInfo DER, the keyid of hosting-modes.md
// 3.7 and the public_key_sha256 the generation script stores in 1Password.
//
// Example:
//
//	keyid, err := transport.Keyid(&privateKey.PublicKey)
func Keyid(key *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encode the admin public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ContentDigest returns the Content-Digest value for body (RFC 9530): a Dictionary with exactly the sha-256
// member, whose value is a Structured Field byte sequence. A request without a body uses the digest of the
// empty byte string, so a body added in transit is detected.
//
// Example:
//
//	transport.ContentDigest(nil) // "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// Sign buffers req's body, sets Content-Digest for it, and signs req with a new nonce and the current time,
// setting Signature-Input and Signature. It replaces any earlier signature, so calling it once per attempt
// gives every retry a fresh created and nonce (hosting-modes.md 5.2). req keeps a replayable body afterwards.
// It fails, leaving the request unsendable rather than unsigned, when req is outside the profile (see
// SignatureBase) or the body is larger than 1 MiB.
//
// Example:
//
//	req, _ := http.NewRequest(http.MethodPost, "https://admin.example.com/v1/users", body)
//	req.Header.Set("Content-Type", "application/json")
//	if err := signer.Sign(req); err != nil {
//		return err
//	}
func (s *Signer) Sign(req *http.Request) error {
	body, err := bufferBody(req)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Digest", ContentDigest(body))

	random := s.Rand
	if random == nil {
		random = rand.Reader
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return fmt.Errorf("read the signature nonce: %w", err)
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}
	input, base, err := SignatureBase(req, SignatureParams{
		Created: now().Unix(),
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		Keyid:   s.keyid,
	})
	if err != nil {
		return err
	}

	digest := sha512.Sum384([]byte(base))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return fmt.Errorf("sign the request: %w", err)
	}
	// RFC 9421 section 3.3.5: r and s as fixed-size big-endian integers, concatenated. The ASN.1 form that
	// crypto.Signer returns is not accepted by the verifier.
	signature := make([]byte, 2*coordinateBytes)
	r.FillBytes(signature[:coordinateBytes])
	ss.FillBytes(signature[coordinateBytes:])

	req.Header.Set("Signature-Input", input)
	req.Header.Set("Signature", SignatureLabel+"=:"+base64.StdEncoding.EncodeToString(signature)+":")
	return nil
}

// SignatureBase returns the Signature-Input header value and the RFC 9421 section 2.5 signature base for req
// and p. The covered components are, in this order, "@method", "@target-uri", "@authority", "content-digest",
// "content-type" when req has a body (req.ContentLength > 0; only POST and PUT may), and "idempotency-key"
// when req has that header; the parameters are created, nonce, keyid, and tag, with no alg and no expires
// (hosting-modes.md 3.2). It reads Content-Digest from req rather than computing it, so the base covers
// exactly the header that is sent.
//
// It fails when req is not a GET, POST, PUT, or DELETE, has a body of unknown length or a body on GET or
// DELETE, has a fragment or user info, lacks Content-Digest (or Content-Type when it has a body), repeats a
// covered header, or when a parameter would need escaping: the admin Worker would refuse such a request, so
// it is better not sent.
//
// Example:
//
//	input, base, err := transport.SignatureBase(req, transport.SignatureParams{
//		Created: 1767225600, Nonce: nonce, Keyid: keyid,
//	})
func SignatureBase(req *http.Request, p SignatureParams) (signatureInput, base string, err error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	// content-type is covered exactly when the request has a body. Four admin operations are a POST or PUT
	// without one (enrollment-links, secrets, group members, grants), and they send no Content-Type; the
	// contract vectors state the rule per body ("post-without-body", "content-type-covered-without-body").
	if req.ContentLength < 0 {
		return "", "", errors.New("the request body has no known length; sign it with Signer.Sign, which buffers it")
	}
	hasBody := req.ContentLength > 0
	switch method {
	case http.MethodGet, http.MethodDelete:
		if hasBody {
			return "", "", fmt.Errorf("the admin API takes no body on %s", method)
		}
	case http.MethodPost, http.MethodPut:
	default:
		return "", "", fmt.Errorf("the admin API has no %s operation to sign", method)
	}
	scheme, authority, err := targetAuthority(req)
	if err != nil {
		return "", "", err
	}

	type component struct{ name, value string }
	components := []component{
		{"@method", method},
		{"@target-uri", scheme + "://" + authority + req.URL.RequestURI()},
		{"@authority", authority},
	}
	digest, err := singleHeader(req.Header, "Content-Digest")
	if err != nil {
		return "", "", err
	}
	components = append(components, component{"content-digest", digest})
	if hasBody {
		contentType, err := singleHeader(req.Header, "Content-Type")
		if err != nil {
			return "", "", err
		}
		components = append(components, component{"content-type", contentType})
	}
	if len(req.Header.Values("Idempotency-Key")) > 0 {
		key, err := singleHeader(req.Header, "Idempotency-Key")
		if err != nil {
			return "", "", err
		}
		components = append(components, component{"idempotency-key", key})
	}

	for _, value := range []string{p.Nonce, p.Keyid} {
		if !plainString(value) {
			return "", "", errors.New("the signature nonce and keyid must be non-empty printable ASCII without quotes or backslashes")
		}
	}
	var params strings.Builder
	params.WriteByte('(')
	for i, c := range components {
		if i > 0 {
			params.WriteByte(' ')
		}
		params.WriteString(strconv.Quote(c.name))
	}
	params.WriteString(");created=" + strconv.FormatInt(p.Created, 10))
	params.WriteString(`;nonce="` + p.Nonce + `";keyid="` + p.Keyid + `";tag="` + SignatureTag + `"`)

	var b strings.Builder
	for _, c := range components {
		b.WriteString(strconv.Quote(c.name) + ": " + c.value + "\n")
	}
	b.WriteString(`"@signature-params": ` + params.String())
	return SignatureLabel + "=" + params.String(), b.String(), nil
}

// targetAuthority returns the lower-case scheme and the authority as RFC 9421 section 2.2.3 normalizes it:
// lower-case, without the scheme's default port. It is taken from what Go puts on the wire (req.Host, or the
// URL's host when that is empty), so the signed authority is the one the admin Worker sees.
func targetAuthority(req *http.Request) (scheme, authority string, err error) {
	u := req.URL
	if u == nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return "", "", errors.New("the admin API URL must be an absolute URL without user info or a fragment")
	}
	scheme = strings.ToLower(u.Scheme)
	authority = req.Host
	if authority == "" {
		authority = u.Host
	}
	authority = strings.ToLower(authority)
	if authority == "" || (scheme != "https" && scheme != "http") {
		return "", "", fmt.Errorf("the admin API URL must be http or https with a host, got %q", scheme)
	}
	if host, port, err := net.SplitHostPort(authority); err == nil {
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			authority = host
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			}
		}
	}
	return scheme, authority, nil
}

// singleHeader returns the one value of a covered header with surrounding whitespace removed (RFC 9421
// section 2.1). A missing or repeated header is an error: the verifier compares one value.
func singleHeader(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) != 1 {
		return "", fmt.Errorf("the request must carry exactly one %s header to be signed, got %d", name, len(values))
	}
	value := strings.Trim(values[0], " \t")
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("the %s header cannot be signed as it is", name)
	}
	return value, nil
}

// plainString reports whether s can be written as a Structured Field string without escapes. The nonce
// (base64url) and keyid (hex) always can; anything else is a caller bug.
func plainString(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// bufferBody reads req's body once, replaces it with a replayable copy, and returns the bytes to digest.
func bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxSignedBodyBytes+1))
	req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read the request body to sign it: %w", err)
	}
	if len(body) > maxSignedBodyBytes {
		return nil, fmt.Errorf("the request body is larger than %d bytes", maxSignedBodyBytes)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	return body, nil
}

// SigningDoer signs every request it sends and sets User-Agent. Put it under RetryingDoer, so each attempt is
// signed again with a new created and nonce: resending an already signed request would be refused as a replay
// whenever an earlier attempt reached the admin Worker (hosting-modes.md 5.2). The Idempotency-Key and the body
// are not changed, so a retried write is still applied at most once.
type SigningDoer struct {
	// Doer sends the signed request.
	Doer Doer
	// Signer signs each request.
	Signer *Signer
	// UserAgent is sent on every request. It is set explicitly because the workers.dev edge refuses some
	// library default User-Agents before the Worker sees them (hosting-modes.md 5.2).
	UserAgent string
}

// Do signs a copy of req and sends it. The caller's request is not modified, apart from its body being read
// once; a retry rebuilds it from GetBody. When signing fails, nothing is sent: an unsigned admin request
// would only be refused.
//
// Example:
//
//	doer := &transport.RetryingDoer{
//		Doer:    &transport.SigningDoer{Doer: client, Signer: signer, UserAgent: "idpctl/1.0.0"},
//		Retries: 2,
//	}
//	resp, err := doer.Do(req)
func (d *SigningDoer) Do(req *http.Request) (*http.Response, error) {
	signed := req.Clone(req.Context())
	if d.UserAgent != "" {
		signed.Header.Set("User-Agent", d.UserAgent)
	}
	if err := d.Signer.Sign(signed); err != nil {
		return nil, fmt.Errorf("sign the admin api request: %w", err)
	}
	return d.Doer.Do(signed)
}
