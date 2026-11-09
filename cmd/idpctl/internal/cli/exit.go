package cli

import (
	"fmt"
	"strings"
)

// Exit codes. Every problem kind of the admin API has its own code so scripts
// can branch on the kind without parsing stderr; idpctl.md records the table.
const (
	// ExitOK means the operation succeeded.
	ExitOK = 0
	// ExitFailure means no problem was returned but the operation did not
	// complete: a transport error, a response that is not the admin API's
	// (such as a Cloudflare error page), or a local I/O error.
	ExitFailure = 1
	// ExitUsage means the arguments, flags, or local configuration were
	// wrong, and nothing was sent.
	ExitUsage = 2

	// ExitValidationFailed is the validation-failed kind (400).
	ExitValidationFailed = 10
	// ExitNotFound is the not-found kind (404).
	ExitNotFound = 11
	// ExitAlreadyExists is the already-exists kind (409).
	ExitAlreadyExists = 12
	// ExitStateConflict is the state-conflict kind (409).
	ExitStateConflict = 13
	// ExitLimitReached is the limit-reached kind (409).
	ExitLimitReached = 14
	// ExitLastPasskey is the last-passkey kind (409).
	ExitLastPasskey = 15
	// ExitAlgorithmDisabled is the algorithm-disabled kind (409).
	ExitAlgorithmDisabled = 16
	// ExitSecretNotReplayable is the secret-not-replayable kind (409).
	ExitSecretNotReplayable = 17
	// ExitIdempotencyKeyReused is the idempotency-key-reused kind (422).
	ExitIdempotencyKeyReused = 18
	// ExitForbidden is the forbidden kind (403).
	ExitForbidden = 19
	// ExitInternal is the internal kind (500).
	ExitInternal = 20
	// ExitUnknownProblem is a problem whose type idpctl does not know, which
	// means the admin Worker is newer than this build.
	ExitUnknownProblem = 21
)

// problemTypePrefix is the fixed part of every problem type URI.
const problemTypePrefix = "urn:ojilab:idp:problem:"

var exitCodes = map[string]int{
	"validation-failed":      ExitValidationFailed,
	"not-found":              ExitNotFound,
	"already-exists":         ExitAlreadyExists,
	"state-conflict":         ExitStateConflict,
	"limit-reached":          ExitLimitReached,
	"last-passkey":           ExitLastPasskey,
	"algorithm-disabled":     ExitAlgorithmDisabled,
	"secret-not-replayable":  ExitSecretNotReplayable,
	"idempotency-key-reused": ExitIdempotencyKeyReused,
	"forbidden":              ExitForbidden,
	"internal":               ExitInternal,
}

// ExitCodeForKind returns the exit code for a problem kind (the part of the
// type URI after urn:ojilab:idp:problem:), or ExitUnknownProblem for a kind
// this build does not know.
func ExitCodeForKind(kind string) int {
	if code, ok := exitCodes[kind]; ok {
		return code
	}
	return ExitUnknownProblem
}

// ProblemError is an RFC 9457 problem returned by the admin API.
type ProblemError struct {
	// Kind is the type URI without urn:ojilab:idp:problem:, or the whole
	// type when it lacks that prefix.
	Kind string
	// Status is the HTTP status the problem carried.
	Status int
	// Title and Detail are the server's English text.
	Title, Detail string
	// Pointers are the JSON Pointers of failing input members
	// (validation-failed only).
	Pointers []string
}

// Error formats the problem as "kind: detail".
func (p *ProblemError) Error() string {
	return fmt.Sprintf("%s: %s", p.Kind, p.Detail)
}

// ExitCode returns the exit code for the problem's kind.
func (p *ProblemError) ExitCode() int {
	return ExitCodeForKind(p.Kind)
}

func kindOf(problemType string) string {
	if kind, ok := strings.CutPrefix(problemType, problemTypePrefix); ok {
		return kind
	}
	return problemType
}

// usageError marks an error found before anything was sent.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}
