// The audit_log row builder shared by the admin Worker (admin operations) and the IdP Worker (the user's own passkey
// operations), so both write one shape (docs/design/data-model.md, docs/design/cross-language-contract.md).
//
// detail_json is never deleted, so a name or free text written into it would outlive a rename and even a break-glass
// deletion of the user (design principle 7). The builder therefore accepts only known members, each checked against
// the format of an ID, an enum, a number, or a time; anything else throws before a statement exists.
import type { SqlStatement, SqlValue } from "./db.js";
import { isClientId, isCredentialId, isUuidV4 } from "./identifiers.js";
import { isProblemKind, type ProblemKind } from "./problems.js";
import { classifyRedirectUri, isPostLogoutRedirectUriRegistrable } from "./redirect-uri-registration.js";

/** What an audit row is about: `user:<id>`, `client:<id>`, `group:<id>`, `schema`, or `none`. */
export type AuditTarget = `user:${string}` | `client:${string}` | `group:${string}` | "schema" | "none";

/**
 * Who wrote the row. An admin is the name the allowlist resolved from the verified RFC 9421 signature and the keyid
 * of that signing key (the SHA-256 of its SPKI DER), written to admin_cert_sha256 with admin_credential
 * `signing-key` (docs/design/hosting-modes.md 3.9); a user row is the user's own passkey operation and carries
 * neither. break_glass rows are written by hand outside the core, so the builder cannot produce them.
 */
export type AuditActor =
  | { readonly kind: "admin"; readonly name: string; readonly keyid: string }
  | { readonly kind: "user" };

/** A detail member's value: an ID, an enum, a number, a time, or a list of such strings. */
export type AuditDetailValue = string | number | readonly string[];

/** The detail_json object, before validation. */
export type AuditDetail = Readonly<Record<string, AuditDetailValue>>;

/** A boolean SQL expression and its parameters, evaluated in the WHERE of a guarded statement. */
export type SqlCondition = {
  readonly sql: string;
  readonly params: readonly SqlValue[];
};

/** The detail members that only SQL may compute, because their values must match the rows in the same batch. */
export const AUDIT_DETAIL_COMPUTED_KEYS = ["newly_enabled", "sessions_deleted"] as const;

/**
 * A detail member computed by a scalar subquery in the same statement.
 *
 * `newly_enabled` is a JSON array of `{user_id, client_id}`; `sessions_deleted` is a count. Their values come from
 * ID columns and COUNT, so they cannot carry a name.
 */
export type AuditComputedMember = {
  readonly key: (typeof AUDIT_DETAIL_COMPUTED_KEYS)[number];
  /** A SELECT returning one column and at most one row. */
  readonly sql: string;
  readonly params: readonly SqlValue[];
};

/** The input of {@link auditSuccessStatement}. */
export type AuditSuccessRow = {
  readonly occurredAt: number;
  readonly actor: AuditActor;
  readonly writerVersion: string;
  readonly operation: string;
  readonly target: AuditTarget;
  readonly detail: AuditDetail;
  /** Members merged into detail_json by SQL. */
  readonly computed?: readonly AuditComputedMember[];
  /**
   * The condition of the write this row records. The row is inserted only when the condition holds, so a write
   * that does not happen leaves no success row (data-model.md: the audit insert precedes the write in the batch).
   */
  readonly guard?: SqlCondition;
};

/** The input of {@link auditFailureStatement}; only the admin Worker writes failure rows. */
export type AuditFailureRow = {
  readonly occurredAt: number;
  readonly actor: Extract<AuditActor, { readonly kind: "admin" }>;
  readonly writerVersion: string;
  readonly operation: string;
  readonly target: AuditTarget;
  readonly problem: ProblemKind;
};

/** Thrown when an audit row would break the contract, most importantly when a detail value could be a name. */
export class InvalidAuditRowError extends Error {
  override readonly name = "InvalidAuditRowError";
}

const OPERATION = /^[a-z]+(?:_[a-z0-9]+)*$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

function isPrincipal(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const [kind, id, ...rest] = value.split(":");
  return rest.length === 0 && (kind === "user" || kind === "group") && id !== undefined && isUuidV4(id);
}

function isUnixSeconds(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function oneOf(...allowed: readonly string[]): (value: unknown) => boolean {
  return (value) => typeof value === "string" && allowed.includes(value);
}

function isString(check: (value: string) => boolean): (value: unknown) => boolean {
  return (value) => typeof value === "string" && check(value);
}

const ALGORITHMS = oneOf("Ed25519", "RS256");

// The only members detail_json may hold. A new operation that needs another member adds it here with a format check,
// so the question "can this be a name?" is answered once, in review of this table.
const DETAIL_MEMBERS: Readonly<Record<string, (value: unknown) => boolean>> = {
  user_id: isString(isUuidV4),
  group_id: isString(isUuidV4),
  client_id: isString(isClientId),
  principal: isPrincipal,
  credential_id: isString(isCredentialId),
  enablement: oneOf("enabled", "disabled"),
  client_type: oneOf("confidential", "public"),
  id_token_alg: ALGORITHMS,
  previous_id_token_alg: ALGORITHMS,
  expires_at: isUnixSeconds,
  sessions_deleted: isUnixSeconds,
  problem: isProblemKind,
  // Redirect URIs are configuration without personal data (data-model.md); each must pass the registration rules.
  redirect_uris: (value) => Array.isArray(value) && value.every((uri) => typeof uri === "string" && classifyRedirectUri(uri) !== null),
  // RP-Initiated Logout's post-logout redirect URIs: the same kind of configuration, with exactly the registration
  // rule. The check runs only on rows being written, never on stored ones, so tightening it cannot reject history.
  post_logout_redirect_uris: (value) =>
    Array.isArray(value) && value.every((uri) => typeof uri === "string" && isPostLogoutRedirectUriRegistrable(uri)),
};

/**
 * Checks an audit target: an ID-bearing target must carry a well-formed ID, never a name.
 *
 * @param target The untrusted target.
 * @returns Whether the target is `schema`, `none`, `user:<uuid>`, `group:<uuid>`, or `client:<client id>`.
 */
export function isAuditTarget(target: string): target is AuditTarget {
  if (target === "schema" || target === "none") return true;
  const separator = target.indexOf(":");
  const kind = target.slice(0, separator);
  const id = target.slice(separator + 1);
  if (separator < 0) return false;
  if (kind === "user" || kind === "group") return isUuidV4(id);
  if (kind === "client") return isClientId(id);
  return false;
}

function validateCommon(row: {
  readonly occurredAt: number;
  readonly actor: AuditActor;
  readonly writerVersion: string;
  readonly operation: string;
  readonly target: string;
}): void {
  if (!isUnixSeconds(row.occurredAt)) throw new InvalidAuditRowError("occurred_at is not UNIX seconds");
  if (row.writerVersion === "") throw new InvalidAuditRowError("writer_version is empty");
  if (!OPERATION.test(row.operation)) throw new InvalidAuditRowError("operation is not a snake_case operation name");
  if (!isAuditTarget(row.target)) throw new InvalidAuditRowError("target is not an ID-bearing target, schema, or none");
  if (row.actor.kind === "admin") {
    if (row.actor.name === "") throw new InvalidAuditRowError("admin_name is empty");
    if (!SHA256_HEX.test(row.actor.keyid)) {
      throw new InvalidAuditRowError("admin_cert_sha256 is not a lowercase hex SHA-256 keyid");
    }
  }
}

function validateDetail(detail: AuditDetail): void {
  for (const [key, value] of Object.entries(detail)) {
    const check = DETAIL_MEMBERS[key];
    if (check === undefined) throw new InvalidAuditRowError(`detail member ${key} is not allowed`);
    if (!check(value)) throw new InvalidAuditRowError(`detail member ${key} has a value of the wrong format`);
  }
}

// The actor's values, in the order of columnsOf.
function actorColumns(actor: AuditActor): readonly SqlValue[] {
  return actor.kind === "admin" ? ["admin", actor.name, actor.keyid, "signing-key"] : ["user", null, null];
}

// A user row names no admin_credential: the column comes with migration 0004, and the IdP Worker's inserts must not
// depend on it, so the IdP Worker keeps working whichever side of 0004 the database is on. The 0004 trigger holds a
// user row's admin_credential to NULL, which the omitted column already is.
function columnsOf(actor: AuditActor): string {
  const credential = actor.kind === "admin" ? ", admin_credential" : "";
  return `occurred_at, actor, admin_name, admin_cert_sha256${credential}, writer_version, operation, target, result, detail_json`;
}

function actorPlaceholders(actor: AuditActor): string {
  return actorColumns(actor)
    .map(() => "?")
    .join(", ");
}

/**
 * Builds the INSERT of one success row, guarded by the condition of the write it records.
 *
 * Put the statement in the same batch as the write and before it, with the same condition: the row then exists
 * exactly when the write happens, and a rejected write leaves no success row (docs/design/data-model.md).
 *
 * @param row The row; `detail` holds only members of the allowed table.
 * @returns An `INSERT … SELECT … WHERE` statement for `Database.batch`.
 * @throws {InvalidAuditRowError} A column breaks the contract: a detail member is unknown or has a value that is not
 *   an ID, enum, number, or time of its member's format (which is what keeps names out); the target is not
 *   `user:<uuid>`, `group:<uuid>`, `client:<client id>`, `schema`, or `none`; the operation is not snake_case; the
 *   time is not UNIX seconds; the writer version is empty; or an admin actor lacks a name or a hex fingerprint.
 */
export function auditSuccessStatement(row: AuditSuccessRow): SqlStatement {
  validateCommon(row);
  validateDetail(row.detail);
  const computed = row.computed ?? [];
  const keys = new Set<string>(Object.keys(row.detail));
  for (const member of computed) {
    if (!(AUDIT_DETAIL_COMPUTED_KEYS as readonly string[]).includes(member.key) || keys.has(member.key)) {
      throw new InvalidAuditRowError(`computed member ${member.key} is not allowed or is set twice`);
    }
    keys.add(member.key);
  }
  // json() turns each subquery result into a JSON value, so an array stays an array and a count stays a number.
  const detailSql =
    computed.length === 0 ? "?" : `json_set(?, ${computed.map((m) => `'$.${m.key}', json((${m.sql}))`).join(", ")})`;
  const guard = row.guard ?? { sql: "1", params: [] };
  return {
    sql: `INSERT INTO audit_log (${columnsOf(row.actor)}) SELECT ?, ${actorPlaceholders(row.actor)}, ?, ?, ?, 'success', ${detailSql} WHERE ${guard.sql}`,
    params: [
      row.occurredAt,
      ...actorColumns(row.actor),
      row.writerVersion,
      row.operation,
      row.target,
      JSON.stringify(row.detail),
      ...computed.flatMap((m) => m.params),
      ...guard.params,
    ],
  };
}

/**
 * Builds the INSERT of one admin failure row.
 *
 * Run it in its own batch after the failed batch rolled back; the row records only the problem kind, never the
 * rejected input, so a malformed value (which may be a name typed into an ID field) never reaches the log.
 *
 * @param row The row; the target is `none` when no validated ID exists yet.
 * @returns A plain INSERT for `Database.batch`.
 * @throws {InvalidAuditRowError} The same column checks as {@link auditSuccessStatement}.
 */
export function auditFailureStatement(row: AuditFailureRow): SqlStatement {
  validateCommon(row);
  return {
    sql: `INSERT INTO audit_log (${columnsOf(row.actor)}) VALUES (?, ${actorPlaceholders(row.actor)}, ?, ?, ?, 'failure', ?)`,
    params: [
      row.occurredAt,
      ...actorColumns(row.actor),
      row.writerVersion,
      row.operation,
      row.target,
      JSON.stringify({ problem: row.problem }),
    ],
  };
}
