package transport_test

// The RFC 9421 admin-signature vectors of contract/testdata/vectors.json, the same file the TypeScript verifier
// reads (docs/design/cross-language-contract.md). The signer arrives in plan step 4 of
// docs/design/hosting-modes.md; until then the signer cases skip, and the rest checks that Go's standard library
// reads the vectors the same way: Content-Digest, keyid, nonce, and the fixed interop signatures.

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
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"testing"
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
			t.Skip("plan step 4 (docs/design/hosting-modes.md 10): the signer must produce signature_input and signature_base")
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
