package cli_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/cli"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

const (
	userID  = "0b9b7c4e-8a1f-4c3e-9d2a-6f1e2d3c4b5a"
	groupID = "5f0e1d2c-3b4a-4958-8776-655443322110"
)

// recorded is one request as the admin API saw it.
type recorded struct {
	Method string
	Path   string
	Query  map[string][]string
	Header http.Header
	Body   []byte
}

// reply is the canned answer the test server gives.
type reply struct {
	Status      int
	ContentType string
	Body        string
}

// harness runs idpctl against an mTLS test server that accepts only the
// certificate the harness issued.
type harness struct {
	t        *testing.T
	certPath string
	keyPEM   []byte
	baseURL  string
	roots    *x509.CertPool

	mu       sync.Mutex
	requests []recorded
	replies  func(r *http.Request, n int) reply
}

func newHarness(t *testing.T, replies func(r *http.Request, n int) reply) *harness {
	t.Helper()
	h := &harness{t: t, replies: replies}
	ca := testpki.NewCA(t)
	key := testpki.NewECDSAKey(t, elliptic.P384())
	certPEM, keyPEM := ca.IssueClient(t, key)
	block, _ := pem.Decode(certPEM)
	wantCert := block.Bytes
	server := ca.NewMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, wantCert) {
			t.Error("the request did not present the admin certificate")
		}
		body, _ := io.ReadAll(r.Body)
		// Until plan step 6 the admin Worker ignores the signature, so the harness is the verifier: every
		// request, retries included, must carry a valid signature by the admin key.
		if err := verifyAdminSignature(r, body, &key.PublicKey); err != nil {
			t.Errorf("%s %s: %v", r.Method, r.URL.Path, err)
		}
		h.mu.Lock()
		h.requests = append(h.requests, recorded{
			Method: r.Method,
			Path:   r.URL.EscapedPath(),
			Query:  r.URL.Query(),
			Header: r.Header.Clone(),
			Body:   body,
		})
		n := len(h.requests)
		h.mu.Unlock()
		answer := h.replies(r, n)
		if answer.ContentType == "" {
			answer.ContentType = "application/json"
		}
		w.Header().Set("Content-Type", answer.ContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(answer.Status)
		_, _ = io.WriteString(w, answer.Body)
	}))
	h.baseURL = server.URL
	h.roots = testpki.RootCAs(server)
	h.keyPEM = keyPEM
	h.certPath = filepath.Join(t.TempDir(), "admin.crt")
	if err := os.WriteFile(h.certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

// fixed answers every request with the same reply.
func fixed(status int, body string) func(*http.Request, int) reply {
	return func(*http.Request, int) reply { return reply{Status: status, Body: body} }
}

type result struct {
	code   int
	stdout string
	stderr string
}

// run invokes idpctl with the host and certificate flags, the key on stdin,
// and no environment.
func (h *harness) run(args ...string) result {
	h.t.Helper()
	return h.runWith(map[string]string{}, append([]string{"--host", "admin.example.test", "--cert", h.certPath}, args...)...)
}

func (h *harness) runWith(env map[string]string, args ...string) result {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code := cli.Run(ctx, args, cli.Options{
		Stdin:   bytes.NewReader(h.keyPEM),
		Stdout:  &stdout,
		Stderr:  &stderr,
		Getenv:  func(name string) string { return env[name] },
		BaseURL: h.baseURL,
		RootCAs: h.roots,
		Backoff: time.Millisecond,
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

var signatureParams = regexp.MustCompile(`^sig1=\([^)]*\);created=(\d+);nonce="([A-Za-z0-9_-]{43})";keyid="([0-9a-f]{64})";tag="idp-admin"$`)

// verifyAdminSignature checks r the way hosting-modes.md 3.8 describes, minus the clock window and the nonce
// store: User-Agent, Content-Digest over the received body, the Signature-Input the covered request implies,
// the keyid of key, and the 96-byte r || s signature over the rebuilt base.
func verifyAdminSignature(r *http.Request, body []byte, key *ecdsa.PublicKey) error {
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "idpctl/") {
		return fmt.Errorf("User-Agent %q", r.Header.Get("User-Agent"))
	}
	if got, want := r.Header.Get("Content-Digest"), transport.ContentDigest(body); got != want {
		return fmt.Errorf("Content-Digest %q, want %q", got, want)
	}
	input := r.Header.Get("Signature-Input")
	m := signatureParams.FindStringSubmatch(input)
	if m == nil {
		return fmt.Errorf("Signature-Input %q", input)
	}
	keyid, err := transport.Keyid(key)
	if err != nil || m[3] != keyid {
		return fmt.Errorf("keyid %s, want %s", m[3], keyid)
	}
	created, _ := strconv.ParseInt(m[1], 10, 64)
	rebuilt, err := http.NewRequest(r.Method, "https://"+r.Host+r.RequestURI, bytes.NewReader(body))
	if err != nil {
		return err
	}
	rebuilt.Header = r.Header.Clone()
	want, base, err := transport.SignatureBase(rebuilt, transport.SignatureParams{Created: created, Nonce: m[2], Keyid: m[3]})
	if err != nil {
		return err
	}
	if input != want {
		return fmt.Errorf("Signature-Input %q, want %q", input, want)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Signature"), "sig1=:"), ":"))
	if err != nil || len(raw) != 96 {
		return fmt.Errorf("Signature %q", r.Header.Get("Signature"))
	}
	digest := sha512.Sum384([]byte(base))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(raw[:48]), new(big.Int).SetBytes(raw[48:])) {
		return fmt.Errorf("the signature does not verify")
	}
	return nil
}

// nonceOf returns the signature nonce of a recorded request.
func nonceOf(r recorded) string {
	if m := signatureParams.FindStringSubmatch(r.Header.Get("Signature-Input")); m != nil {
		return m[2]
	}
	return ""
}

func (h *harness) seen() []recorded {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recorded(nil), h.requests...)
}

func jsonEqual(t *testing.T, got, want []byte) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Errorf("not JSON: %q: %v", got, err)
		return false
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("bad fixture %q: %v", want, err)
	}
	return reflect.DeepEqual(g, w)
}
