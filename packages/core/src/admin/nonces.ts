// The replay check of the admin signatures (docs/design/hosting-modes.md 3.6, item 10 of 3.8): the port the admin
// Worker calls after verifyAdminSignature passed, and the SQL an adapter runs for it. The SQL stays here, with the
// other rules of the core, so an adapter only runs the statements and reads the result.
import type { SqlStatement } from "../shared/index.js";

/** Thrown when the nonce store fails for a reason other than the nonce being taken. */
export class AdminNonceStoreError extends Error {
  override readonly name = "AdminNonceStoreError";
}

/** Whether a claim stored the nonce (`fresh`) or found it already stored (`replayed`). */
export type AdminNonceClaim = "fresh" | "replayed";

/** Stores the nonces of verified admin signatures so that each nonce is accepted once. */
export interface AdminNonceStore {
  /**
   * Stores a verified signature's nonce unless it is already stored, and deletes the nonces that expired before `now`
   * in the same transaction (no cron: docs/design/hosting-modes.md 3.6).
   *
   * Call only after the signature and the body digest passed, so an unauthenticated request writes nothing, and
   * before the operation's writes, so a later failure of the operation still leaves the nonce used. Not idempotent
   * by design: the second claim of a nonce reports `replayed` even when the first claim's response was lost.
   *
   * @param nonce The signature's `nonce` parameter, already checked as strict base64url of 32 bytes.
   * @param expiresAt `created` plus the window, in UNIX seconds.
   * @param now The admin Worker's clock, in UNIX seconds; rows with `expires_at` before it are deleted. A deleted
   *   nonce can be stored again, which is safe because the window refuses a request whose nonce has expired.
   * @returns `fresh` when this call stored the nonce; `replayed` when a row with the same nonce already exists.
   * @throws {AdminNonceStoreError} The store failed or was unreachable, so whether the nonce is new is unknown; the
   *   caller refuses the request with `internal` (fail-closed).
   */
  claim(nonce: string, expiresAt: number, now: number): Promise<AdminNonceClaim>;
}

/**
 * The statements of one claim, to run as one batch: the sweep of expired rows, then the insert.
 *
 * The insert does nothing on a conflict with the primary key, so the unique constraint decides the replay and the
 * adapter reads it from the insert's change count (1 is fresh, 0 is replayed) instead of matching error messages.
 *
 * @param nonce The nonce to store.
 * @param expiresAt Its expiry, in UNIX seconds.
 * @param now The clock, in UNIX seconds.
 * @returns The sweep and the insert, in that order.
 */
export function adminNonceClaimStatements(nonce: string, expiresAt: number, now: number): readonly [SqlStatement, SqlStatement] {
  return [
    { sql: "DELETE FROM admin_request_nonces WHERE expires_at < ?", params: [now] },
    { sql: "INSERT INTO admin_request_nonces (nonce, expires_at) VALUES (?, ?) ON CONFLICT (nonce) DO NOTHING", params: [nonce, expiresAt] },
  ];
}
