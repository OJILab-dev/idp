// The problem kinds of the admin API (docs/design/idpctl.md, "エラーの形"). They live in shared because failure
// audit rows record the kind, and the audit-row builder must recognise every value it lets into detail_json.

/** Every `kind` of `urn:ojilab:idp:problem:<kind>`, the single list the OpenAPI spec is generated from. */
export const PROBLEM_KINDS = [
  "validation-failed",
  "not-found",
  "already-exists",
  "state-conflict",
  "limit-reached",
  "last-passkey",
  "algorithm-disabled",
  "secret-not-replayable",
  "idempotency-key-reused",
  "forbidden",
  "internal",
] as const;

/** One admin API problem kind. */
export type ProblemKind = (typeof PROBLEM_KINDS)[number];

/**
 * Checks whether a value is one of {@link PROBLEM_KINDS}.
 *
 * @param value The untrusted value.
 * @returns Whether the value names a problem kind.
 */
export function isProblemKind(value: unknown): value is ProblemKind {
  return (PROBLEM_KINDS as readonly unknown[]).includes(value);
}
