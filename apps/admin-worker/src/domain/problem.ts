// RFC 9457 problem details for the admin API (docs/design/idpctl.md, "エラーの形"). The core decides the kind; the
// admin Worker only serialises it, so every rule's outcome has one spelling across HTTP, idpctl, and the audit log.
import type { ProblemDetails as Rfc9457ProblemDetails } from "@idp/problem-details";
import type { ProblemKind } from "@idp/core/problems";

/** The HTTP status of each problem kind. */
export const PROBLEM_STATUS: Readonly<Record<ProblemKind, number>> = {
  "validation-failed": 400,
  "not-found": 404,
  "already-exists": 409,
  "state-conflict": 409,
  "limit-reached": 409,
  "last-passkey": 409,
  "algorithm-disabled": 409,
  "secret-not-replayable": 409,
  "idempotency-key-reused": 422,
  forbidden: 403,
  internal: 500,
};

// RFC 9457 §3.1.3: the title does not change between occurrences of a type, so it is fixed per kind.
const PROBLEM_TITLE: Readonly<Record<ProblemKind, string>> = {
  "validation-failed": "The request is not valid",
  "not-found": "The resource does not exist",
  "already-exists": "The resource already exists",
  "state-conflict": "The resource is already in the requested state or cannot change in its current state",
  "limit-reached": "The user has reached the passkey limit",
  "last-passkey": "The last passkey of a user cannot be revoked",
  "algorithm-disabled": "The signing algorithm is not enabled in this deployment",
  "secret-not-replayable": "A response that carried a secret cannot be replayed",
  "idempotency-key-reused": "The Idempotency-Key was already used for a different request",
  forbidden: "Forbidden",
  internal: "Internal error",
};

/**
 * The `application/problem+json` body of the admin API: an RFC 9457 problem details object whose type, title,
 * status, and detail are always present, plus the failing fields of a validation problem as an extension member.
 */
export type ProblemDetails = Rfc9457ProblemDetails<{
  readonly type: `urn:ojilab:idp:problem:${ProblemKind}`;
  readonly title: string;
  readonly status: number;
  readonly detail: string;
  /** JSON Pointers (RFC 6901) into the operation input; present only for `validation-failed`. */
  readonly errors?: readonly string[];
}>;

/**
 * Builds the problem `type` URI of a kind.
 *
 * @param kind The problem kind.
 * @returns `urn:ojilab:idp:problem:<kind>`.
 */
export function problemType(kind: ProblemKind): `urn:ojilab:idp:problem:${ProblemKind}` {
  return `urn:ojilab:idp:problem:${kind}`;
}

/** Thrown by an admin operation when a rule rejects the request; carries everything the problem body needs. */
export class AdminProblem extends Error {
  override readonly name = "AdminProblem";
  readonly kind: ProblemKind;
  /** JSON Pointers of the failing fields, for `validation-failed`; empty otherwise. */
  readonly pointers: readonly string[];

  /**
   * @param kind The problem kind.
   * @param detail An English sentence for the operator; never a secret, token, SQL, or stack trace.
   * @param options The failing fields for a validation problem, and the underlying cause.
   */
  constructor(kind: ProblemKind, detail: string, options: { readonly pointers?: readonly string[]; readonly cause?: unknown } = {}) {
    super(detail, options.cause === undefined ? undefined : { cause: options.cause });
    this.kind = kind;
    this.pointers = options.pointers ?? [];
  }

  /**
   * Serialises the problem as RFC 9457 problem details.
   *
   * @returns The body; `internal` problems carry a generic detail so internals never leave the Worker.
   */
  toProblemDetails(): ProblemDetails {
    const base = {
      type: problemType(this.kind),
      title: PROBLEM_TITLE[this.kind],
      status: PROBLEM_STATUS[this.kind],
      detail: this.kind === "internal" ? "The request failed; see the admin Worker log" : this.message,
    };
    return this.kind === "validation-failed" ? { ...base, errors: this.pointers } : base;
  }
}
