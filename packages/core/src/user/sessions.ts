// The IdP session as the OIDC endpoints read it. Sessions are created by the passkey sign-in, not here; these helpers
// only look a session up by its cookie and check access through effective_access, the one access definition.
import { isRandomTokenFormat, sha256Base64url, type Database } from "../shared/index.js";
import { CorruptRowError } from "./clients.js";
import type { OidcDeps } from "./deps.js";

/** How long a session lives from the sign-in; it is never extended (NIST SP 800-63B-4 AAL2, authentication.md). */
export const SESSION_LIFETIME_SECONDS = 3600;

/** A session row that has not expired. */
export type ActiveSession = {
  readonly tokenHash: string;
  readonly userId: string;
  /** The passkey the user signed in with; revoking it ends the session through the foreign key. */
  readonly credentialId: string;
  /** When the user signed in with a passkey, in UNIX seconds. */
  readonly authTime: number;
};

/**
 * Looks up the session a cookie names.
 *
 * @param deps The database and the clock.
 * @param sessionToken The cookie value, untrusted; `undefined` when the cookie is absent.
 * @returns The session, or `undefined` when the cookie is absent, malformed, unknown, or expired.
 * @throws {CorruptRowError} The row's columns do not have the schema's types.
 * @throws {DatabaseError} The read failed.
 */
export async function findActiveSession(
  deps: Pick<OidcDeps, "db" | "clock">,
  sessionToken: string | undefined,
): Promise<ActiveSession | undefined> {
  if (sessionToken === undefined || !isRandomTokenFormat(sessionToken)) return undefined;
  const tokenHash = await sha256Base64url(sessionToken);
  const [result] = await deps.db.batch([
    {
      sql: "SELECT user_id, credential_id, auth_time FROM sessions WHERE token_hash = ? AND expires_at > ?",
      params: [tokenHash, deps.clock.now()],
    },
  ]);
  const row = result?.rows[0];
  if (row === undefined) return undefined;
  const userId = row["user_id"];
  const credentialId = row["credential_id"];
  const authTime = row["auth_time"];
  if (typeof userId !== "string" || typeof credentialId !== "string" || typeof authTime !== "number") {
    throw new CorruptRowError("session row is malformed");
  }
  return { tokenHash, userId, credentialId, authTime };
}

/**
 * Ends the current session (`POST /logout`). Only this session's row is deleted; the user's other sessions stay.
 * The unused codes issued from it go with it through the foreign key (data-model.md).
 *
 * Idempotent: an absent, malformed, unknown, or already deleted cookie is a no-op, so the HTTP layer can always clear
 * the cookie and report success. The same-origin check belongs to the HTTP layer.
 *
 * @param deps The database.
 * @param sessionToken The session cookie's value; `undefined` when absent.
 * @throws {DatabaseError} The delete failed.
 */
export async function logout(deps: Pick<OidcDeps, "db">, sessionToken: string | undefined): Promise<void> {
  if (sessionToken === undefined || !isRandomTokenFormat(sessionToken)) return;
  await deps.db.batch([{ sql: "DELETE FROM sessions WHERE token_hash = ?", params: [await sha256Base64url(sessionToken)] }]);
}

/**
 * Checks whether a user may use a client right now.
 *
 * @param db The database.
 * @param userId The user.
 * @param clientId The client.
 * @returns Whether `effective_access` has the pair, which also requires the user and client (and a granting group)
 *   to be enabled.
 * @throws {DatabaseError} The read failed.
 */
export async function hasAccess(db: Database, userId: string, clientId: string): Promise<boolean> {
  const [result] = await db.batch([
    { sql: "SELECT 1 AS ok FROM effective_access WHERE user_id = ? AND client_id = ?", params: [userId, clientId] },
  ]);
  return (result?.rows.length ?? 0) > 0;
}
