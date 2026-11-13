// The replay check of the admin signatures (docs/design/hosting-modes.md 3.6, item 10 of 3.8): the store the admin
// Worker calls after verifyAdminSignature passed, written against the Database port so that the SQL and the reading
// of its result stay with the other admin rules; the platform only supplies the Database.
import { DatabaseError, type Database, type SqlStatement } from "@idp/db";
import { ADMIN_SIGNATURE_WINDOW_SECONDS } from "./signature.js";

/** Thrown when the nonce store fails for a reason other than the nonce being taken. */
export class AdminNonceStoreError extends Error {
  override readonly name = "AdminNonceStoreError";
}

/** Whether a claim stored the nonce (`fresh`) or found it already stored (`replayed`). */
export type AdminNonceClaim = "fresh" | "replayed";

/** Stores the nonces of verified admin signatures so that each nonce is accepted once. */
export interface AdminNonceStore {
  /**
   * Stores a verified signature's nonce unless it is already stored, and deletes the nonces that expired more than one
   * window before `now` in the same transaction (no cron: docs/design/hosting-modes.md 3.6).
   *
   * Call only after the signature and the body digest passed, so an unauthenticated request writes nothing, and
   * before the operation's writes, so a later failure of the operation still leaves the nonce used. Not idempotent
   * by design: the second claim of a nonce reports `replayed` even when the first claim's response was lost.
   *
   * @param nonce The signature's `nonce` parameter, already checked as strict base64url of 32 bytes.
   * @param expiresAt `created` plus the window, in UNIX seconds.
   * @param now The admin Worker's clock at verification, in UNIX seconds; rows with `expires_at` more than one window
   *   before it are deleted. The grace matters because another request's sweep runs with its own, later clock while
   *   a replay verified at the end of the window (its `now` equal to `expires_at`) is still on its way to the store:
   *   without the grace, that sweep could delete the row and let the replay claim the nonce as fresh. With it, a row
   *   is deleted only once every request that could still carry the nonce is a full window past verification.
   * @returns `fresh` when this call stored the nonce; `replayed` when a row with the same nonce already exists.
   * @throws {AdminNonceStoreError} `expiresAt` or `now` is not a safe integer (nothing is written); or the store
   *   failed or was unreachable, so whether the nonce is new is unknown. Either way the caller refuses the request
   *   with `internal` (fail-closed).
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
 * @throws {AdminNonceStoreError} `expiresAt` or `now` is not a safe integer: a NaN clock would make the sweep's
 *   comparison meaningless, so no statement is built.
 */
function adminNonceClaimStatements(nonce: string, expiresAt: number, now: number): readonly [SqlStatement, SqlStatement] {
  if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(now)) {
    throw new AdminNonceStoreError("expiresAt and now must be safe integers");
  }
  return [
    // One window of grace (see AdminNonceStore.claim): the table holds at most about two windows of rows.
    { sql: "DELETE FROM admin_request_nonces WHERE expires_at < ?", params: [now - ADMIN_SIGNATURE_WINDOW_SECONDS] },
    { sql: "INSERT INTO admin_request_nonces (nonce, expires_at) VALUES (?, ?) ON CONFLICT (nonce) DO NOTHING", params: [nonce, expiresAt] },
  ];
}

/**
 * Builds the {@link AdminNonceStore} on a {@link Database}.
 *
 * Each claim runs the sweep and the insert of {@link adminNonceClaimStatements} as one batch, so they commit together,
 * and reads the insert's change count: one row means the nonce was new, none means it was already stored.
 *
 * @param db The database the admin Worker composed from its D1 binding.
 * @returns An {@link AdminNonceStore} whose `claim` rejects only with {@link AdminNonceStoreError}: a
 *   {@link DatabaseError} from the batch is wrapped with the cause kept, and a change count other than 0 or 1 is
 *   refused rather than guessed at.
 */
export function createAdminNonceStore(db: Database): AdminNonceStore {
  return {
    async claim(nonce: string, expiresAt: number, now: number): Promise<AdminNonceClaim> {
      let changes: number | undefined;
      try {
        changes = (await db.batch(adminNonceClaimStatements(nonce, expiresAt, now)))[1]?.changes;
      } catch (cause) {
        if (cause instanceof DatabaseError) throw new AdminNonceStoreError(`nonce claim failed: ${cause.message}`, { cause });
        throw cause;
      }
      if (changes === 1) return "fresh";
      if (changes === 0) return "replayed";
      // Any other count means the statement did not do what this module wrote; refuse rather than guess.
      throw new AdminNonceStoreError(`nonce insert changed ${String(changes)} rows`);
    },
  };
}
