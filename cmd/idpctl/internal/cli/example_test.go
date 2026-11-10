package cli_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/cli"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
)

// exampleServer starts a throwaway HTTPS admin API that answers every
// request with reply, and returns the options to reach it with a throwaway
// admin key on stdin.
func exampleServer(t *testing.T, status int, contentType, reply string) (cli.Options, func()) {
	server := testpki.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	opts := cli.Options{
		Stdin:   bytes.NewReader(testpki.EncodePKCS8(t, testpki.NewECDSAKey(t, elliptic.P384()))),
		Stdout:  os.Stdout,
		Stderr:  io.Discard,
		Getenv:  func(string) string { return "" },
		BaseURL: server.URL,
		RootCAs: testpki.RootCAs(server),
	}
	return opts, server.Close
}

// ExampleRun creates a user. The admin private key arrives on stdin, signs
// the request, and the JSON result is printed to stdout.
func ExampleRun() {
	opts, cleanup := exampleServer(&testing.T{}, 201, "application/json", `{"user_id":"0b9b7c4e-8a1f-4c3e-9d2a-6f1e2d3c4b5a"}`)
	defer cleanup()

	code := cli.Run(context.Background(), []string{"--host", "admin.example.test", "user_create", "Alice"}, opts)
	fmt.Println("exit", code)
	// Output:
	// {
	//   "user_id": "0b9b7c4e-8a1f-4c3e-9d2a-6f1e2d3c4b5a"
	// }
	// exit 0
}

// ExampleRun_problem shows a problem turning into its kind's exit code.
func ExampleRun_problem() {
	opts, cleanup := exampleServer(&testing.T{}, 409, "application/problem+json",
		`{"type":"urn:ojilab:idp:problem:last-passkey","title":"Last passkey","status":409,"detail":"The last passkey cannot be revoked."}`)
	defer cleanup()

	code := cli.Run(context.Background(), []string{"--host", "admin.example.test", "passkey_revoke", "0b9b7c4e-8a1f-4c3e-9d2a-6f1e2d3c4b5a", "Y3JlZA"}, opts)
	fmt.Println(code == cli.ExitLastPasskey)
	// Output: true
}

// ExampleOperations prints the first subcommands; they are the admin API
// operation names.
func ExampleOperations() {
	fmt.Println(strings.Join(cli.Operations()[:3], " "))
	// Output: users_list user_get clients_list
}

// ExampleExitCodeForKind maps problem kinds to exit codes.
func ExampleExitCodeForKind() {
	fmt.Println(cli.ExitCodeForKind("not-found"), cli.ExitCodeForKind("a-kind-from-a-newer-worker"))
	// Output: 11 21
}

// ExampleProblemError shows how a problem reads as an error.
func ExampleProblemError() {
	err := &cli.ProblemError{Kind: "state-conflict", Status: 409, Title: "State conflict", Detail: "The user is already disabled."}
	fmt.Println(err, err.ExitCode())
	// Output: state-conflict: The user is already disabled. 13
}
