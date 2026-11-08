// Package cli implements idpctl's subcommands: one per admin API operation,
// named exactly as the operation. It parses arguments, calls the admin API
// through the generated client over mTLS, prints the JSON result, writes
// IdP-issued secrets to a new 0600 file instead of the terminal, and turns
// RFC 9457 problems into exit codes. It evaluates no domain rule: the admin
// Worker is the only judge, and idpctl shows what it answers.
package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/adminapi"
	"github.com/OJILab-dev/idp/cmd/idpctl/internal/transport"
)

// Environment variables that supply defaults for --host and --cert.
const (
	EnvHost = "IDPCTL_HOST"
	EnvCert = "IDPCTL_CERT"
)

// maxKeyBytes bounds what is read from stdin; a PEM private key is far
// smaller, and anything larger is not one.
const maxKeyBytes = 64 << 10

// Options carries the process environment into Run so tests can replace it.
type Options struct {
	// Stdin supplies the admin private key PEM, the only place idpctl reads
	// it from.
	Stdin io.Reader
	// Stdout receives the JSON result; Stderr receives logs and problems.
	Stdout, Stderr io.Writer
	// Getenv looks up IDPCTL_HOST and IDPCTL_CERT.
	Getenv func(string) string
	// BaseURL replaces https://<host> as the API base. Tests only: it lets
	// them reach an httptest server, which listens on an IP and a port that
	// --host refuses.
	BaseURL string
	// RootCAs replaces the system roots. Tests only.
	RootCAs *x509.CertPool
	// Backoff is the wait before the first retry. Zero means 500ms.
	Backoff time.Duration
}

type globals struct {
	host, cert string
	retries    int
	timeout    time.Duration
	verbose    bool
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.host, "host", g.host, "admin API host name (default $"+EnvHost+")")
	fs.StringVar(&g.cert, "cert", g.cert, "path of the admin client certificate PEM (default $"+EnvCert+")")
	fs.IntVar(&g.retries, "retries", g.retries, "retries after a lost or edge-unavailable response; writes reuse their Idempotency-Key")
	fs.DurationVar(&g.timeout, "timeout", g.timeout, "timeout of each attempt")
	fs.BoolVar(&g.verbose, "v", g.verbose, "log debug messages")
}

// call is what an operation needs to send its request.
type call struct {
	api *adminapi.ClientWithResponses
	// key is this invocation's Idempotency-Key. Writes that require one send
	// it; RetryingDoer resends the same request, so retries reuse it.
	key string
}

// Run executes idpctl with args (without the program name) and returns the
// process exit code. Logs and problems go to opts.Stderr as slog text; the
// result goes to opts.Stdout as indented JSON.
func Run(ctx context.Context, args []string, opts Options) int {
	level := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(opts.Stderr, &slog.HandlerOptions{Level: level}))
	err := run(ctx, args, opts, logger, level)

	var problem *ProblemError
	var usage *usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.As(err, &usage):
		logger.Error("invalid usage; run idpctl help", slog.String("error", usage.msg))
		return ExitUsage
	case errors.As(err, &problem):
		attrs := []any{
			slog.String("kind", problem.Kind),
			slog.Int("status", problem.Status),
			slog.String("title", problem.Title),
			slog.String("detail", problem.Detail),
		}
		if len(problem.Pointers) > 0 {
			attrs = append(attrs, slog.String("errors", strings.Join(problem.Pointers, " ")))
		}
		logger.Error("the admin api returned a problem", attrs...)
		return problem.ExitCode()
	default:
		logger.Error("idpctl failed", slog.String("error", err.Error()))
		return ExitFailure
	}
}

func run(ctx context.Context, args []string, opts Options, logger *slog.Logger, level *slog.LevelVar) error {
	g := globals{host: opts.Getenv(EnvHost), cert: opts.Getenv(EnvCert), retries: 2, timeout: 30 * time.Second}
	top := flag.NewFlagSet("idpctl", flag.ContinueOnError)
	top.SetOutput(io.Discard)
	g.register(top)
	if err := top.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printOverview(opts.Stdout)
			return err
		}
		return usagef("%v", err)
	}
	rest := top.Args()
	if len(rest) == 0 {
		return usagef("no operation given")
	}
	if rest[0] == "help" {
		printOverview(opts.Stdout)
		return nil
	}
	op := lookup(rest[0])
	if op == nil {
		return usagef("unknown operation %q", rest[0])
	}

	var f opFlags
	fs := flag.NewFlagSet(op.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.register(fs)
	registerFlags(fs, op.flags, &f)
	positional, err := parseInterleaved(fs, rest[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printOperation(opts.Stdout, op, fs)
			return err
		}
		return usagef("%s: %v", op.name, err)
	}
	if len(positional) < op.args || (!op.variadic && len(positional) != op.args) {
		return usagef("usage: idpctl %s %s", op.name, op.synopsis)
	}
	secret := op.secret(&f)
	switch {
	case secret != "" && f.secretOut == "":
		return usagef("%s returns %s, which idpctl never prints: pass --secret-out with a new file path", op.name, secret)
	case secret == "" && f.secretOut != "":
		return usagef("%s returns no secret; drop --secret-out", op.name)
	}
	if g.verbose {
		level.Set(slog.LevelDebug)
	}

	api, err := connect(&g, opts, logger)
	if err != nil {
		return err
	}
	key, err := transport.NewIdempotencyKey()
	if err != nil {
		return err
	}

	var out *secretFile
	if secret != "" {
		// The file is created before the request so a bad path fails
		// before the admin Worker issues a secret nobody could store.
		if out, err = createSecretFile(f.secretOut); err != nil {
			return err
		}
		defer out.discard()
	}

	logger.Debug("calling the admin api", slog.String("operation", op.name), slog.String("host", g.host))
	resp, err := op.send(ctx, &call{api: api, key: key}, positional, &f)
	if err != nil {
		if out != nil {
			// The admin Worker may have issued the secret before the
			// response was lost; it is not stored, so the only way forward
			// is a fresh issue that replaces it.
			logger.Info("no response arrived; a secret may have been issued and lost", slog.String("next_step", recoveryHint(op.name)))
		}
		return fmt.Errorf("%s: %w", op.name, err)
	}
	body, err := interpret(resp)
	if err != nil {
		var problem *ProblemError
		if errors.As(err, &problem) && problem.Kind == "secret-not-replayable" {
			logger.Info("the response held a secret and was not stored", slog.String("next_step", recoveryHint(op.name)))
		}
		return err
	}
	if out != nil {
		if body, err = out.store(body, secret); err != nil {
			return fmt.Errorf("%s succeeded but %w; %s", op.name, err, recoveryHint(op.name))
		}
	}
	return printJSON(opts.Stdout, body)
}

// connect validates the local configuration, reads the key from stdin, and
// builds the generated client on top of the mTLS transport.
func connect(g *globals, opts Options, logger *slog.Logger) (*adminapi.ClientWithResponses, error) {
	if g.host == "" {
		return nil, usagef("no admin host: pass --host or set %s", EnvHost)
	}
	if err := checkHost(g.host); err != nil {
		return nil, err
	}
	if g.cert == "" {
		return nil, usagef("no client certificate: pass --cert or set %s", EnvCert)
	}
	certPEM, err := os.ReadFile(g.cert)
	if err != nil {
		return nil, fmt.Errorf("read the client certificate: %w", err)
	}
	keyPEM, err := io.ReadAll(io.LimitReader(opts.Stdin, maxKeyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the private key from stdin: %w", err)
	}
	// Best effort: the key bytes do not outlive the parse in this buffer.
	defer clear(keyPEM)
	if len(bytes.TrimSpace(keyPEM)) == 0 {
		return nil, usagef("no private key: pipe the admin private key PEM on stdin; idpctl reads it from nowhere else")
	}
	if len(keyPEM) > maxKeyBytes {
		return nil, usagef("stdin holds more than %d bytes, which is not a private key PEM", maxKeyBytes)
	}
	cert, err := transport.LoadClientCertificate(certPEM, keyPEM)
	if err != nil {
		return nil, usagef("%v", err)
	}

	backoff := opts.Backoff
	if backoff == 0 {
		backoff = 500 * time.Millisecond
	}
	doer := &transport.RetryingDoer{
		Doer:    transport.NewHTTPClient(transport.Config{Certificate: cert, RootCAs: opts.RootCAs, Timeout: g.timeout}),
		Retries: max(g.retries, 0),
		Backoff: backoff,
		Logger:  logger,
	}
	base := "https://" + g.host
	if opts.BaseURL != "" {
		base = opts.BaseURL
	}
	return adminapi.NewClientWithResponses(base, adminapi.WithHTTPClient(doer))
}

// checkHost accepts a bare, lower-case DNS host name. idpctl.md keeps the
// admin host as the only setting and requires its canonical form without a
// port; a scheme, path, port, or IP address here is a configuration mistake
// that would send the client certificate somewhere unintended.
func checkHost(host string) error {
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() != host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return usagef("--host must be a bare host name, got %q", host)
	}
	if net.ParseIP(host) != nil || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return usagef("--host must be a lower-case DNS name without a trailing dot, got %q", host)
	}
	return nil
}

// parseInterleaved lets flags follow positional arguments, as in
// "client_create grafana Grafana --public"; arguments after "--" are all
// positional.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// interpret returns the body of a success, or the problem the admin Worker
// returned, or an error for anything else (such as the edge's block page).
func interpret(resp response) ([]byte, error) {
	media, _, _ := mime.ParseMediaType(resp.ContentType())
	status := resp.StatusCode()
	body := resp.GetBody()
	if status >= 200 && status < 300 {
		if media != "application/json" || !json.Valid(body) {
			return nil, fmt.Errorf("the admin api answered %d with %q instead of a JSON body", status, media)
		}
		return body, nil
	}
	if media != "application/problem+json" {
		return nil, fmt.Errorf("the admin api answered %d with %q instead of a problem; the edge may have blocked the request", status, media)
	}
	var p adminapi.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("the admin api answered %d with a malformed problem: %w", status, err)
	}
	problem := &ProblemError{Kind: kindOf(string(p.Type)), Status: p.Status, Title: p.Title, Detail: p.Detail}
	if p.Errors != nil {
		problem.Pointers = *p.Errors
	}
	return nil, problem
}

func recoveryHint(operation string) string {
	if operation == "client_create" {
		return "the client exists; run client_rotate_secret to issue a new secret"
	}
	return "run " + operation + " again; the new secret replaces the one that was not received"
}

func printJSON(w io.Writer, body []byte) error {
	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	_, err := w.Write(out.Bytes())
	return err
}

func printOverview(w io.Writer) {
	fmt.Fprintln(w, "usage: idpctl [--host HOST] [--cert PATH] [--retries N] [--timeout D] [-v] <operation> [arguments] < admin-key.pem")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The admin private key PEM is read from stdin only. Run idpctl <operation> -h for its flags.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "operations:")
	for _, op := range operations {
		fmt.Fprintf(w, "  %-24s %s\n", op.name, op.summary)
	}
}

func printOperation(w io.Writer, op *operation, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage: idpctl %s %s [flags] < admin-key.pem\n\n%s\n\nflags:\n", op.name, op.synopsis, op.summary)
	fs.SetOutput(w)
	fs.PrintDefaults()
}
