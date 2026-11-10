package cli_test

import (
	"crypto/elliptic"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/cli"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
)

func problem(status int, kind, detail string, extra string) reply {
	return reply{
		Status:      status,
		ContentType: "application/problem+json",
		Body: `{"type":"urn:ojilab:idp:problem:` + kind + `","title":"Problem","status":` +
			strconv.Itoa(status) + `,"detail":"` + detail + `"` + extra + `}`,
	}
}

func TestProblemsPrintTheKindAndMapToExitCodes(t *testing.T) {
	cases := []struct {
		status int
		kind   string
		code   int
	}{
		{400, "validation-failed", cli.ExitValidationFailed},
		{404, "not-found", cli.ExitNotFound},
		{409, "already-exists", cli.ExitAlreadyExists},
		{409, "state-conflict", cli.ExitStateConflict},
		{409, "limit-reached", cli.ExitLimitReached},
		{409, "last-passkey", cli.ExitLastPasskey},
		{409, "algorithm-disabled", cli.ExitAlgorithmDisabled},
		{409, "secret-not-replayable", cli.ExitSecretNotReplayable},
		{422, "idempotency-key-reused", cli.ExitIdempotencyKeyReused},
		{403, "forbidden", cli.ExitForbidden},
		{500, "internal", cli.ExitInternal},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			h := newHarness(t, func(*http.Request, int) reply { return problem(tc.status, tc.kind, "Something is wrong.", "") })
			got := h.run("user_disable", userID)
			if got.code != tc.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", got.code, tc.code, got.stderr)
			}
			if !strings.Contains(got.stderr, "kind="+tc.kind) || !strings.Contains(got.stderr, "Something is wrong.") {
				t.Errorf("stderr lacks the kind or detail:\n%s", got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout %q, want nothing", got.stdout)
			}
			if n := len(h.seen()); n != 1 {
				t.Errorf("%d requests: problems must not be retried", n)
			}
		})
	}
}

// TestEveryProblemKindHasItsOwnExitCode reads the kinds from the spec so a
// kind added to the shared core cannot fall through to a generic exit code.
func TestEveryProblemKindHasItsOwnExitCode(t *testing.T) {
	spec := readSpec(t)
	kinds := spec.Components.Schemas.Problem.Properties.Type.Enum
	if len(kinds) == 0 {
		t.Fatal("no problem kinds in the spec")
	}
	seen := map[int]string{}
	for _, uri := range kinds {
		kind := strings.TrimPrefix(uri, "urn:ojilab:idp:problem:")
		code := cli.ExitCodeForKind(kind)
		if code == cli.ExitUnknownProblem {
			t.Errorf("kind %s has no exit code", kind)
		}
		if other, dup := seen[code]; dup {
			t.Errorf("kinds %s and %s share exit code %d", kind, other, code)
		}
		seen[code] = kind
	}
}

func TestValidationFailedPrintsThePointers(t *testing.T) {
	h := newHarness(t, func(*http.Request, int) reply {
		return problem(400, "validation-failed", "Invalid input.", `,"errors":["/name","/redirect_uris/0"]`)
	})
	got := h.run("user_create", " ")
	if got.code != cli.ExitValidationFailed {
		t.Fatalf("exit %d", got.code)
	}
	if !strings.Contains(got.stderr, "/name") || !strings.Contains(got.stderr, "/redirect_uris/0") {
		t.Errorf("stderr lacks the JSON Pointers:\n%s", got.stderr)
	}
}

func TestUnknownProblemTypeAndNonProblemResponses(t *testing.T) {
	h := newHarness(t, func(*http.Request, int) reply {
		return reply{Status: 409, ContentType: "application/problem+json",
			Body: `{"type":"urn:ojilab:idp:problem:brand-new","title":"New","status":409,"detail":"New rule."}`}
	})
	if got := h.run("user_get", userID); got.code != cli.ExitUnknownProblem || !strings.Contains(got.stderr, "brand-new") {
		t.Errorf("unknown kind: exit %d, stderr:\n%s", got.code, got.stderr)
	}

	// Cloudflare's edge answers with its own error or block page, not a problem.
	h = newHarness(t, func(*http.Request, int) reply {
		return reply{Status: 403, ContentType: "text/html", Body: "<html>blocked</html>"}
	})
	if got := h.run("user_get", userID); got.code != cli.ExitFailure || !strings.Contains(got.stderr, "403") {
		t.Errorf("edge block: exit %d, stderr:\n%s", got.code, got.stderr)
	}

	h = newHarness(t, func(*http.Request, int) reply {
		return reply{Status: 200, ContentType: "text/plain", Body: "ok"}
	})
	if got := h.run("user_get", userID); got.code != cli.ExitFailure || got.stdout != "" {
		t.Errorf("non-JSON success: exit %d, stdout %q", got.code, got.stdout)
	}
}

func TestEachInvocationUsesAFreshIdempotencyKey(t *testing.T) {
	h := newHarness(t, fixed(201, `{"user_id":"`+userID+`"}`))
	for range 2 {
		if got := h.run("user_create", "Alice"); got.code != 0 {
			t.Fatalf("exit %d: %s", got.code, got.stderr)
		}
	}
	r := h.seen()
	if r[0].Header.Get("Idempotency-Key") == r[1].Header.Get("Idempotency-Key") {
		t.Fatal("two invocations shared an Idempotency-Key")
	}
}

func TestRetriesReuseTheIdempotencyKey(t *testing.T) {
	h := newHarness(t, func(_ *http.Request, n int) reply {
		if n < 3 {
			return reply{Status: 503, ContentType: "text/html", Body: "<html>unavailable</html>"}
		}
		return reply{Status: 201, Body: `{"user_id":"` + userID + `"}`}
	})
	got := h.run("--retries", "2", "user_create", "Alice")
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	r := h.seen()
	if len(r) != 3 {
		t.Fatalf("%d attempts, want 3", len(r))
	}
	nonces := map[string]bool{}
	for i := range r {
		if r[i].Header.Get("Idempotency-Key") != r[0].Header.Get("Idempotency-Key") || string(r[i].Body) != string(r[0].Body) {
			t.Fatalf("attempt %d changed the key or body", i)
		}
		// Each attempt is signed again: resending the same signature would be refused as a replay whenever
		// the earlier attempt reached the admin Worker.
		if nonce := nonceOf(r[i]); nonce == "" || nonces[nonce] {
			t.Fatalf("attempt %d reused or lacks a signature nonce", i)
		} else {
			nonces[nonce] = true
		}
	}
	if !strings.Contains(got.stderr, "attempt=1") {
		t.Errorf("retries are not logged:\n%s", got.stderr)
	}

	h = newHarness(t, func(*http.Request, int) reply {
		return reply{Status: 503, ContentType: "text/html", Body: "<html>unavailable</html>"}
	})
	if got := h.run("--retries", "0", "user_create", "Alice"); got.code != cli.ExitFailure || len(h.seen()) != 1 {
		t.Fatalf("--retries 0: exit %d, %d attempts", got.code, len(h.seen()))
	}
}

func TestSecretsGoToA0600FileAndNeverToTheOutput(t *testing.T) {
	const secret = "c2VjcmV0LXZhbHVlLXRoYXQtbXVzdC1uZXZlci1sZWFr"
	const link = "https://idp.example/enroll#token=" + secret
	cases := []struct {
		name     string
		args     []string
		method   string
		path     string
		body     string
		response string
		value    string
	}{
		{
			name: "client_create", args: []string{"client_create", "grafana", "Grafana", "--redirect-uri", "https://grafana.example/cb", "--id-token-alg", "RS256"},
			method: http.MethodPost, path: "/v1/clients",
			body:     `{"client_id":"grafana","name":"Grafana","client_type":"confidential","redirect_uris":["https://grafana.example/cb"],"id_token_alg":"RS256"}`,
			response: `{"client_id":"grafana","client_type":"confidential","client_secret":"` + secret + `"}`,
			value:    secret,
		},
		{
			name: "client_rotate_secret", args: []string{"client_rotate_secret", "grafana"},
			method: http.MethodPost, path: "/v1/clients/grafana/secrets",
			response: `{"client_id":"grafana","client_secret":"` + secret + `"}`,
			value:    secret,
		},
		{
			name: "enroll_link_issue", args: []string{"enroll_link_issue", userID},
			method: http.MethodPost, path: "/v1/users/" + userID + "/enrollment-links",
			response: `{"user_id":"` + userID + `","enrollment_link":"` + link + `","expires_at":1700000600}`,
			value:    link,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, fixed(201, tc.response))
			out := filepath.Join(t.TempDir(), "secret")
			got := h.run(append(tc.args, "--secret-out", out)...)
			if got.code != 0 {
				t.Fatalf("exit %d: %s", got.code, got.stderr)
			}
			r := h.seen()
			if len(r) != 1 || r[0].Method != tc.method || r[0].Path != tc.path {
				t.Fatalf("requests %+v", r)
			}
			if !idempotencyKeyShape.MatchString(r[0].Header.Get("Idempotency-Key")) {
				t.Errorf("Idempotency-Key %q", r[0].Header.Get("Idempotency-Key"))
			}
			if tc.body != "" && !jsonEqual(t, r[0].Body, []byte(tc.body)) {
				t.Errorf("body %s, want %s", r[0].Body, tc.body)
			}
			if strings.Contains(got.stdout, secret) || strings.Contains(got.stderr, secret) {
				t.Fatalf("the secret reached the terminal:\nstdout %s\nstderr %s", got.stdout, got.stderr)
			}
			if !strings.Contains(got.stdout, out) {
				t.Errorf("stdout does not show the file path:\n%s", got.stdout)
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("mode %v, want 0600", info.Mode().Perm())
			}
			content, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != tc.value+"\n" {
				t.Errorf("file holds %q", content)
			}
		})
	}
}

func TestSecretFileIsCheckedBeforeTheRequestAndRemovedOnFailure(t *testing.T) {
	h := newHarness(t, fixed(201, `{"client_id":"grafana","client_secret":"x"}`))
	existing := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := h.run("client_rotate_secret", "grafana", "--secret-out", existing); got.code != cli.ExitFailure {
		t.Errorf("existing file: exit %d", got.code)
	}
	if content, _ := os.ReadFile(existing); string(content) != "keep" {
		t.Error("an existing file was overwritten")
	}
	if got := h.run("client_rotate_secret", "grafana"); got.code != cli.ExitUsage {
		t.Errorf("missing --secret-out: exit %d", got.code)
	}
	if got := h.run("client_create", "grafana", "Grafana", "--redirect-uri", "https://g.example/cb"); got.code != cli.ExitUsage {
		t.Errorf("confidential client without --secret-out: exit %d", got.code)
	}
	if n := len(h.seen()); n != 0 {
		t.Fatalf("%d requests sent before the secret file was ready", n)
	}

	h = newHarness(t, func(*http.Request, int) reply { return problem(404, "not-found", "No such client.", "") })
	out := filepath.Join(t.TempDir(), "secret")
	if got := h.run("client_rotate_secret", "missing", "--secret-out", out); got.code != cli.ExitNotFound {
		t.Fatalf("exit %d", got.code)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the secret file was left behind after a failure: %v", err)
	}
}

// TestStraySecretsAreNeverPrinted covers a server bug that returns a secret
// member to an operation that did not route it to --secret-out: idpctl must
// fail and keep the value off the terminal.
func TestStraySecretsAreNeverPrinted(t *testing.T) {
	const secret = "c3RyYXktc2VjcmV0LXRoYXQtbXVzdC1uZXZlci1sZWFr"
	cases := []struct {
		name     string
		args     []string
		status   int
		response string
	}{
		{"public client_create with client_secret", []string{"client_create", "cli", "CLI", "--public", "--redirect-uri", "http://127.0.0.1/cb"},
			201, `{"client_id":"cli","client_type":"public","client_secret":"` + secret + `"}`},
		{"user_get with enrollment_link", []string{"user_get", userID},
			200, `{"user_id":"` + userID + `","name":"Alice","enablement":"enabled","created_at":1,"passkeys":[],"enrollment_link":"https://idp.example/enroll#` + secret + `"}`},
		{"nested client_secret", []string{"clients_list"},
			200, `{"items":[{"client_id":"g","name":"G","client_type":"confidential","enablement":"enabled","redirect_uris":[],"id_token_alg":"Ed25519","created_at":1,"client_secret":"` + secret + `"}],"next_cursor":null,"prev_cursor":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, fixed(tc.status, tc.response))
			got := h.run(tc.args...)
			if got.code != cli.ExitFailure {
				t.Fatalf("exit %d, want %d; stderr:\n%s", got.code, cli.ExitFailure, got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout %q, want nothing", got.stdout)
			}
			if strings.Contains(got.stderr, secret) {
				t.Errorf("the secret reached stderr:\n%s", got.stderr)
			}
		})
	}
}

// TestASecondSecretAfterTheRoutedOneRemovesTheFile checks that the file is
// kept only when the whole output was safe to print, so the "issue it again"
// message is accurate whenever idpctl fails after writing the file.
func TestASecondSecretAfterTheRoutedOneRemovesTheFile(t *testing.T) {
	const secret = "c2Vjb25kLXNlY3JldC10aGF0LW11c3QtbmV2ZXItbGVhaw"
	h := newHarness(t, fixed(201, `{"client_id":"grafana","client_secret":"first","enrollment_link":"https://idp.example/enroll#`+secret+`"}`))
	out := filepath.Join(t.TempDir(), "secret")
	got := h.run("client_rotate_secret", "grafana", "--secret-out", out)
	if got.code != cli.ExitFailure || got.stdout != "" || strings.Contains(got.stderr, secret) {
		t.Fatalf("exit %d, stdout %q, stderr:\n%s", got.code, got.stdout, got.stderr)
	}
	if !strings.Contains(got.stderr, "client_rotate_secret again") {
		t.Errorf("stderr lacks the recovery hint:\n%s", got.stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the secret file was kept although idpctl failed: %v", err)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	for _, n := range []string{"-1", "11"} {
		if got := h.run("--retries", n, "users_list"); got.code != cli.ExitUsage {
			t.Errorf("--retries %s: exit %d", n, got.code)
		}
	}
	if got := h.run("--retries", "10", "users_list"); got.code != 0 {
		t.Errorf("--retries 10: exit %d: %s", got.code, got.stderr)
	}
	if n := len(h.seen()); n != 1 {
		t.Fatalf("%d requests, want only the valid one", n)
	}
}

func TestSecretNotReplayableExplainsHowToRecover(t *testing.T) {
	h := newHarness(t, func(*http.Request, int) reply {
		return problem(409, "secret-not-replayable", "The response held a secret and was not stored.", "")
	})
	got := h.run("client_create", "grafana", "Grafana", "--redirect-uri", "https://g.example/cb", "--secret-out", filepath.Join(t.TempDir(), "s"))
	if got.code != cli.ExitSecretNotReplayable || !strings.Contains(got.stderr, "client_rotate_secret") {
		t.Fatalf("exit %d, stderr:\n%s", got.code, got.stderr)
	}
}

func TestForbiddenListsWhatToCheck(t *testing.T) {
	h := newHarness(t, func(*http.Request, int) reply { return problem(403, "forbidden", "Forbidden.", "") })
	got := h.run("users_list")
	if got.code != cli.ExitForbidden {
		t.Fatalf("exit %d, stderr:\n%s", got.code, got.stderr)
	}
	for _, want := range []string{"clock", "admin_signing_keys", "host", "keyid="} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, got.stderr)
		}
	}
}

func TestOnlyAP384KeyCanSign(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	ca := testpki.NewCA(t)
	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P256()))
	if err := os.WriteFile(h.certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	h.keyPEM = keyPEM
	if got := h.run("users_list"); got.code != cli.ExitUsage || !strings.Contains(got.stderr, "P-384") {
		t.Fatalf("P-256 key: exit %d, stderr:\n%s", got.code, got.stderr)
	}
	if n := len(h.seen()); n != 0 {
		t.Fatalf("%d requests with a P-256 key", n)
	}
}

func TestConfigurationComesFromFlagsOrEnvironment(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	env := map[string]string{"IDPCTL_HOST": "admin.example.test", "IDPCTL_CERT": h.certPath}
	if got := h.runWith(env, "users_list"); got.code != 0 {
		t.Fatalf("environment: exit %d: %s", got.code, got.stderr)
	}
	if got := h.runWith(map[string]string{}, "users_list"); got.code != cli.ExitUsage || !strings.Contains(got.stderr, "IDPCTL_HOST") {
		t.Errorf("missing host: exit %d, stderr:\n%s", got.code, got.stderr)
	}
	if got := h.runWith(map[string]string{"IDPCTL_HOST": "admin.example.test"}, "users_list"); got.code != cli.ExitUsage || !strings.Contains(got.stderr, "IDPCTL_CERT") {
		t.Errorf("missing cert: exit %d, stderr:\n%s", got.code, got.stderr)
	}
	for _, host := range []string{"https://admin.example.test", "admin.example.test:443", "admin.example.test/v1", "192.0.2.1", "Admin.Example.Test", "user@admin.example.test"} {
		if got := h.runWith(map[string]string{}, "--host", host, "--cert", h.certPath, "users_list"); got.code != cli.ExitUsage {
			t.Errorf("host %q accepted: exit %d", host, got.code)
		}
	}
	if n := len(h.seen()); n != 1 {
		t.Fatalf("%d requests, want only the valid one", n)
	}
}

func TestThePrivateKeyIsReadOnlyFromStdin(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	h.keyPEM = nil
	got := h.run("users_list")
	if got.code != cli.ExitUsage || !strings.Contains(got.stderr, "stdin") {
		t.Fatalf("exit %d, stderr:\n%s", got.code, got.stderr)
	}
	if got := h.run("--key", "/tmp/admin.key", "users_list"); got.code != cli.ExitUsage {
		t.Errorf("a key flag was accepted: exit %d", got.code)
	}
	if n := len(h.seen()); n != 0 {
		t.Fatalf("%d requests without a key", n)
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	for _, args := range [][]string{
		{},
		{"user_delete", userID},
		{"user_get"},
		{"user_get", userID, "extra"},
		{"users_list", "--limit"},
		{"grant_add", "group:" + groupID},
		{"client_create", "cli", "CLI", "--public", "--secret-out", "/tmp/x"},
		{"client_set_redirects", "grafana"},
	} {
		if got := h.run(args...); got.code != cli.ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, got.code, cli.ExitUsage)
		}
	}
	if n := len(h.seen()); n != 0 {
		t.Fatalf("%d requests from usage errors", n)
	}
}

func TestHelpListsEveryOperation(t *testing.T) {
	h := newHarness(t, fixed(200, emptyPage))
	got := h.runWith(map[string]string{}, "help")
	if got.code != 0 {
		t.Fatalf("exit %d", got.code)
	}
	for _, name := range cli.Operations() {
		if !strings.Contains(got.stdout, name) {
			t.Errorf("help omits %s", name)
		}
	}
	if got := h.runWith(map[string]string{}, "user_get", "-h"); got.code != 0 || !strings.Contains(got.stdout, "user_get") {
		t.Errorf("operation help: exit %d, stdout %q", got.code, got.stdout)
	}
}
