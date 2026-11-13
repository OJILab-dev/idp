// Idempotency-Key for the creating and appending POSTs of the admin API (docs/design/idpctl.md, "Idempotency-Key";
// draft-ietf-httpapi-idempotency-key-header-08). Keys live in a per-admin namespace for 24 hours, and the row is
// written in the operation's own batch under the operation's guard, so the stored response and the change commit
// together or not at all.
import { canonicalize } from "@idp/json-canonicalization";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isRandomTokenFormat } from "../identifiers/index.js";
import type { SqlCondition, SqlRow, SqlStatement } from "../db/index.js";
import type { OperationName, OperationOutcome } from "./operation.js";
import { AdminProblem } from "./problem.js";

/** How long a key is remembered. */
export const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;

// An optional member the validated input leaves undefined counts as absent, as it always has, so the input is the
// same JSON value whether the member was omitted or validated away.
function withoutAbsentMembers(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutAbsentMembers);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, member]) => member !== undefined)
        .map(([name, member]) => [name, withoutAbsentMembers(member)]),
    );
  }
  return value;
}

/**
 * Hashes a request for idempotency_keys.request_hash: SHA-256, unpadded base64url, of the input's RFC 8785 canonical
 * JSON, so equal inputs hash equally whatever their member order on the wire.
 *
 * The hash covers the whole validated input, path parameters included: the body of an enablement event is the same
 * for every user, so hashing the body alone would replay one user's response for another.
 *
 * @param input The validated operation input.
 * @returns The hash.
 * @throws {JsonCanonicalizationError} The input holds a value JSON cannot carry; validated input never does.
 */
export function requestHash(input: unknown): Promise<string> {
  return sha256Base64url(canonicalize(withoutAbsentMembers(input)));
}

/**
 * Validates the Idempotency-Key header value.
 *
 * @param key The header value; undefined when absent.
 * @returns The key.
 * @throws {AdminProblem} `validation-failed` when the header is absent (draft §2.7) or is not 32 random bytes as
 *   unpadded base64url (docs/design/cross-language-contract.md).
 */
export function requireIdempotencyKey(key: string | undefined): string {
  if (key === undefined || !isRandomTokenFormat(key)) {
    throw new AdminProblem("validation-failed", "The Idempotency-Key header is required and must be 32 random bytes as base64url");
  }
  return key;
}

/**
 * Builds the read of a live key of this admin.
 *
 * @param adminName The admin's name, the namespace of the key.
 * @param key The validated key.
 * @param now The current time in UNIX seconds; expired rows are ignored.
 * @returns The statement; its rows are zero or one row of idempotency_keys.
 */
export function idempotencyLookupStatement(adminName: string, key: string, now: number): SqlStatement {
  return {
    sql:
      "SELECT operation, request_hash, replayable, response_status, response_json FROM idempotency_keys " +
      "WHERE admin_name = ? AND idempotency_key = ? AND expires_at > ?",
    params: [adminName, key, now],
  };
}

/**
 * Builds the cleanup of expired keys, run first in every batch that writes a key (docs/design/data-model.md).
 *
 * @param now The current time in UNIX seconds.
 * @returns The DELETE statement.
 */
export function idempotencyCleanupStatement(now: number): SqlStatement {
  return { sql: "DELETE FROM idempotency_keys WHERE expires_at <= ?", params: [now] };
}

/** The row an operation stores with its key. */
export type IdempotencyRecord = {
  readonly adminName: string;
  readonly key: string;
  readonly operation: OperationName;
  readonly requestHash: string;
  /** The response to replay, or null when it carries a secret (replayable = 0). */
  readonly response: { readonly status: number; readonly body: unknown } | null;
  readonly now: number;
  /** The operation's guard; no key is stored when the operation does not happen. */
  readonly guard: SqlCondition;
};

/**
 * Builds the guarded INSERT of a key. A concurrent request with the same key fails here on the primary key, and the
 * caller then replays the row the winner stored.
 *
 * @param record The row.
 * @returns The `INSERT … SELECT … WHERE` statement.
 */
export function idempotencyInsertStatement(record: IdempotencyRecord): SqlStatement {
  return {
    sql:
      "INSERT INTO idempotency_keys (admin_name, idempotency_key, operation, request_hash, replayable, response_status, " +
      `response_json, expires_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${record.guard.sql}`,
    params: [
      record.adminName,
      record.key,
      record.operation,
      record.requestHash,
      record.response === null ? 0 : 1,
      record.response?.status ?? null,
      record.response === null ? null : JSON.stringify(record.response.body),
      record.now + IDEMPOTENCY_TTL_SECONDS,
      ...record.guard.params,
    ],
  };
}

/**
 * Answers a request whose key is already stored.
 *
 * @param row The stored row.
 * @param operation The operation of the repeated request.
 * @param hash The request hash of the repeated request.
 * @returns The stored response, marked as replayed.
 * @throws {AdminProblem} `idempotency-key-reused` when the operation or the request differs (draft §2.2, §2.7);
 *   `secret-not-replayable` when the stored operation returned a secret and kept no response.
 */
export function replayStored<R>(row: SqlRow, operation: OperationName, hash: string): OperationOutcome<R> {
  if (row["operation"] !== operation || row["request_hash"] !== hash) {
    throw new AdminProblem("idempotency-key-reused", "This Idempotency-Key was used for a different request");
  }
  if (row["replayable"] !== 1) {
    throw new AdminProblem(
      "secret-not-replayable",
      "The original response carried a secret and was not kept; retry with a new Idempotency-Key",
    );
  }
  const status = row["response_status"];
  return {
    status: status === 201 ? 201 : 200,
    body: JSON.parse(row["response_json"] as string) as R,
    replayed: true,
  };
}
