// Command idpctl is the thin admin CLI of the idp: each subcommand calls one
// admin API operation, signing every request with the admin private key
// (RFC 9421, the only admin authentication), and prints the JSON result. The
// admin private key PEM is read from stdin only, IdP-issued secrets are written to a new
// 0600 file named by --secret-out, and problems become exit codes. See
// docs/design/idpctl.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.Options{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
	})
	stop()
	os.Exit(code)
}
