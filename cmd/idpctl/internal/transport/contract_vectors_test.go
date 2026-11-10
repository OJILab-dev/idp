package transport_test

// The RFC 9421 admin-signature vectors of contract/testdata/vectors.json, the same file the TypeScript verifier
// reads (docs/design/cross-language-contract.md). The signer cases check that idpctl's signer produces the
// vectors' Signature-Input and signature base character for character, and that its signatures verify over the
// verifier's valid cases; the rest checks that Go's standard library reads the vectors the same way:
// Content-Digest, keyid, nonce, and the fixed interop signatures.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

type signedRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  [][2]string `json:"headers"`
	BodyUTF8 string      `json:"body_utf8"`
}

type verifyCase struct {
	Case            string        `json:"case"`
	Reason          string        `json:"reason"`
	Request         signedRequest `json:"request"`
	SignatureBase   *string       `json:"signature_base"`
	Key             string        `json:"key"`
	SignatureTamper string        `json:"signature_tamper"`
}

type adminSignatureVectors struct {
	Profile struct {
		Label                  string   `json:"label"`
		Tag                    string   `json:"tag"`
		Algorithm              string   `json:"algorithm"`
		FallbackAlgorithm      string   `json:"fallback_algorithm"`
		SignatureBytes         int      `json:"signature_bytes"`
		WindowSeconds          int      `json:"window_seconds"`
		NonceBytes             int      `json:"nonce_bytes"`
		ContentDigestAlgorithm string   `json:"content_digest_algorithm"`
		Components             []string `json:"components"`
		Parameters             []string `json:"parameters"`
	} `json:"profile"`
	ContentDigest struct {
		Valid []struct {
			Source   string `json:"source"`
			BodyUTF8 string `json:"body_utf8"`
			Header   string `json:"header"`
		} `json:"valid"`
		Invalid []struct {
			BodyUTF8 string `json:"body_utf8"`
			Header   string `json:"header"`
			Reason   string `json:"reason"`
		} `json:"invalid"`
	} `json:"content_digest"`
	Keyid struct {
		Valid []struct {
			Source string `json:"source"`
			SPKI   string `json:"spki"`
			Keyid  string `json:"keyid"`
		} `json:"valid"`
		Invalid []struct {
			Value  string `json:"value"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	} `json:"keyid"`
	Nonce struct {
		Valid   []string `json:"valid"`
		Invalid []struct {
			Value  string `json:"value"`
			Reason string `json:"reason"`
		} `json:"invalid"`
	} `json:"nonce"`
	SignatureBase []struct {
		Case           string        `json:"case"`
		Request        signedRequest `json:"request"`
		Created        int64         `json:"created"`
		Nonce          string        `json:"nonce"`
		Keyid          string        `json:"keyid"`
		SignatureInput string        `json:"signature_input"`
		SignatureBase  string        `json:"signature_base"`
	} `json:"signature_base"`
	Interop []struct {
		Case          string `json:"case"`
		Source        string `json:"source"`
		Algorithm     string `json:"algorithm"`
		SPKI          string `json:"spki"`
		SignatureBase string `json:"signature_base"`
		Signature     string `json:"signature"`
	} `json:"interop"`
	Verify struct {
		Now       int64        `json:"now"`
		AdminHost string       `json:"admin_host"`
		Valid     []verifyCase `json:"valid"`
		Invalid   []verifyCase `json:"invalid"`
		Replay    verifyCase   `json:"replay"`
	} `json:"verify"`
}

// loadAdminSignatureVectors decodes only the admin_signature section, rejecting members this struct does not
// know, so that a vector added on the TypeScript side cannot be silently ignored here.
func loadAdminSignatureVectors(t *testing.T) adminSignatureVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "contract", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	section, ok := all["admin_signature"]
	if !ok {
		t.Fatal("vectors.json has no admin_signature")
	}
	decoder := json.NewDecoder(bytes.NewReader(section))
	decoder.DisallowUnknownFields()
	var v adminSignatureVectors
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("decode admin_signature: %v", err)
	}
	return v
}

func sha256ContentDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// strictNonce is the strict base64url of cross-language-contract.md: no padding, canonical trailing bits.
var strictNonce = base64.RawURLEncoding.Strict()

func TestAdminSignatureVectorsProfile(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	if v.Profile.Algorithm != "ecdsa-p384-sha384" || v.Profile.SignatureBytes != 96 || v.Profile.Tag != "idp-admin" || v.Profile.Label != "sig1" {
		t.Fatalf("unexpected profile: %+v", v.Profile)
	}
	if len(v.SignatureBase) == 0 || len(v.Verify.Valid) == 0 || len(v.Verify.Invalid) == 0 {
		t.Fatal("the vectors have no signer or verifier cases")
	}
}

func TestAdminSignatureVectorsContentDigest(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	for _, c := range v.ContentDigest.Valid {
		if got := sha256ContentDigest(c.BodyUTF8); got != c.Header {
			t.Errorf("%s: got %q, want %q", c.Source, got, c.Header)
		}
	}
	for _, c := range v.ContentDigest.Invalid {
		if sha256ContentDigest(c.BodyUTF8) == c.Header {
			t.Errorf("%s: the invalid header is the accepted form", c.Reason)
		}
	}
	// The sha-512 vector is not accepted, but it must still be a real digest so that the verifier's rejection
	// comes from the algorithm and not from a malformed value.
	sum := sha512.Sum512(nil)
	want := "sha-512=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if v.ContentDigest.Invalid[1].Header != want {
		t.Errorf("sha-512 only: got %q, want %q", v.ContentDigest.Invalid[1].Header, want)
	}
}

func TestAdminSignatureVectorsKeyid(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	for _, c := range v.Keyid.Valid {
		spki, err := base64.StdEncoding.DecodeString(c.SPKI)
		if err != nil {
			t.Fatalf("%s: %v", c.Source, err)
		}
		sum := sha256.Sum256(spki)
		if got := hex.EncodeToString(sum[:]); got != c.Keyid {
			t.Errorf("%s: got %s, want %s", c.Source, got, c.Keyid)
		}
	}
	lowerHex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, c := range v.Keyid.Invalid {
		if lowerHex.MatchString(c.Value) {
			t.Errorf("%s: %q has the valid form", c.Reason, c.Value)
		}
	}
}

func TestAdminSignatureVectorsNonce(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	for _, n := range v.Nonce.Valid {
		decoded, err := strictNonce.DecodeString(n)
		if err != nil || len(decoded) != v.Profile.NonceBytes {
			t.Errorf("%q: got %d bytes, err %v", n, len(decoded), err)
		}
	}
	for _, c := range v.Nonce.Invalid {
		decoded, err := strictNonce.DecodeString(c.Value)
		if err == nil && len(decoded) == v.Profile.NonceBytes {
			t.Errorf("%s: %q decodes to %d bytes", c.Reason, c.Value, len(decoded))
		}
	}
}

// TestAdminSignatureVectorsInterop verifies the fixed signatures with the standard library, the same primitives
// the signer will use: a P-384 signature is r and s as 48-byte big-endian integers, concatenated.
func TestAdminSignatureVectorsInterop(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	for _, c := range v.Interop {
		t.Run(c.Case, func(t *testing.T) {
			der, err := base64.StdEncoding.DecodeString(c.SPKI)
			if err != nil {
				t.Fatal(err)
			}
			public, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := base64.StdEncoding.DecodeString(c.Signature)
			if err != nil {
				t.Fatal(err)
			}
			switch c.Algorithm {
			case "ecdsa-p384-sha384":
				key, ok := public.(*ecdsa.PublicKey)
				if !ok || key.Curve.Params().Name != "P-384" || len(signature) != 96 {
					t.Fatalf("not a P-384 key and a 96-byte signature: %T, %d bytes", public, len(signature))
				}
				digest := sha512.Sum384([]byte(c.SignatureBase))
				r := new(big.Int).SetBytes(signature[:48])
				s := new(big.Int).SetBytes(signature[48:])
				if !ecdsa.Verify(key, digest[:], r, s) {
					t.Fatal("the P-384 signature does not verify")
				}
				tampered := sha512.Sum384([]byte(c.SignatureBase + " "))
				if ecdsa.Verify(key, tampered[:], r, s) {
					t.Fatal("the P-384 signature verifies over a changed base")
				}
			case "ed25519":
				key, ok := public.(ed25519.PublicKey)
				if !ok || !ed25519.Verify(key, []byte(c.SignatureBase), signature) {
					t.Fatal("the Ed25519 signature does not verify")
				}
			default:
				t.Fatalf("unknown algorithm %q", c.Algorithm)
			}
		})
	}
}

func TestAdminSignatureVectorsSigner(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	for _, c := range v.SignatureBase {
		t.Run(c.Case, func(t *testing.T) {
			if got := sha256ContentDigest(c.Request.BodyUTF8); !hasHeader(c.Request, "Content-Digest", got) {
				t.Fatalf("the request's Content-Digest is not %q", got)
			}

			// The pure base: the vector's created, nonce, and keyid give the vector's strings, character for
			// character.
			input, base, err := transport.SignatureBase(vectorRequest(t, c.Request), transport.SignatureParams{
				Created: c.Created, Nonce: c.Nonce, Keyid: c.Keyid,
			})
			if err != nil {
				t.Fatal(err)
			}
			if input != c.SignatureInput {
				t.Errorf("Signature-Input\n got %s\nwant %s", input, c.SignatureInput)
			}
			if base != c.SignatureBase {
				t.Errorf("signature base\n got %q\nwant %q", base, c.SignatureBase)
			}

			// The full signer, from a request that carries no Content-Digest yet: the key is a test key, so its
			// keyid replaces the vector's, and everything else must match.
			signer, key := fixedSigner(t, c.Created, c.Nonce)
			req := vectorRequest(t, c.Request)
			req.Header.Del("Content-Digest")
			if err := signer.Sign(req); err != nil {
				t.Fatal(err)
			}
			keyid := keyidOf(t, &key.PublicKey)
			if signer.Keyid() != keyid {
				t.Fatalf("Keyid() = %s, want %s", signer.Keyid(), keyid)
			}
			if got := req.Header.Get("Content-Digest"); !hasHeader(c.Request, "Content-Digest", got) {
				t.Errorf("Content-Digest %q", got)
			}
			if got, want := req.Header.Get("Signature-Input"), strings.ReplaceAll(c.SignatureInput, c.Keyid, keyid); got != want {
				t.Errorf("Signature-Input\n got %s\nwant %s", got, want)
			}
			verifySignature(t, &key.PublicKey, req.Header.Get("Signature"), strings.ReplaceAll(c.SignatureBase, c.Keyid, keyid))
			var body []byte
			if req.Body != nil {
				body, _ = io.ReadAll(req.Body)
			}
			if string(body) != c.Request.BodyUTF8 {
				t.Errorf("the signed request sends body %q, want %q", body, c.Request.BodyUTF8)
			}
		})
	}
}

// TestSignerSatisfiesTheVerifierValidCases signs each verify.valid request of the vectors and checks the result
// against the vector's own signature base, so the signer and the verifier agree on the same inputs.
func TestSignerSatisfiesTheVerifierValidCases(t *testing.T) {
	v := loadAdminSignatureVectors(t)
	nonceOf := regexp.MustCompile(`;nonce="([^"]+)"`)
	createdOf := regexp.MustCompile(`;created=(\d+)`)
	for _, c := range v.Verify.Valid {
		t.Run(c.Case, func(t *testing.T) {
			var input string
			for _, h := range c.Request.Headers {
				if h[0] == "Signature-Input" {
					input = h[1]
				}
			}
			created, err := strconv.ParseInt(createdOf.FindStringSubmatch(input)[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			signer, key := fixedSigner(t, created, nonceOf.FindStringSubmatch(input)[1])
			req := vectorRequest(t, c.Request)
			for _, name := range []string{"Content-Digest", "Signature-Input", "Signature"} {
				req.Header.Del(name)
			}
			if err := signer.Sign(req); err != nil {
				t.Fatal(err)
			}
			keyid := keyidOf(t, &key.PublicKey)
			if got, want := req.Header.Get("Signature-Input"), strings.ReplaceAll(input, "{keyid}", keyid); got != want {
				t.Errorf("Signature-Input\n got %s\nwant %s", got, want)
			}
			verifySignature(t, &key.PublicKey, req.Header.Get("Signature"), strings.ReplaceAll(*c.SignatureBase, "{keyid}", keyid))
		})
	}
}

func hasHeader(r signedRequest, name, value string) bool {
	for _, h := range r.Headers {
		if h[0] == name && h[1] == value {
			return true
		}
	}
	return false
}
