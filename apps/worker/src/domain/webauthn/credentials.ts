// GET /webauthn/credentials (docs/design/authentication.md, the account page): the session user's own passkeys,
// limited to the fields the page shows, plus the RP ID and the user's own user handle that the page needs to tell the
// browser which passkeys are still accepted (WebAuthn Level 3 signalAllAcceptedCredentials). Public keys, sign counts,
// and other users never leave the database here. The Sec-Fetch-Site check and Cache-Control: no-store belong to the
// HTTP layer.
import { base64urlEncode } from "@idp/base64url";
import { userEnabledCondition } from "@idp/passkeys";
import { CorruptRowError } from "../clients.js";
import type { PasskeyDeps } from "../deps.js";
import { findActiveSession } from "../sessions.js";
import { bytesColumn, integerColumn, rejected, textColumn, type PasskeyRejection } from "./ceremony.js";

/** One passkey as the account page lists it. */
export type OwnPasskey = {
  readonly credential_id: string;
  readonly created_at: number;
  /** `null` until the passkey is first used. */
  readonly last_used_at: number | null;
  /** Bound through an enrollment link, or added by the user while signed in. */
  readonly created_via: "enroll" | "self";
  /** The backup state flag: whether the passkey is synced to other devices. */
  readonly backup_state: boolean;
};

/** The result of {@link listOwnPasskeys}. */
export type OwnPasskeysResult =
  | {
      readonly kind: "passkeys";
      readonly passkeys: readonly OwnPasskey[];
      /** The RP ID the passkeys are scoped to. */
      readonly rpId: string;
      /** The session user's WebAuthn user handle (users.user_handle), base64url without padding. */
      readonly userHandle: string;
    }
  | PasskeyRejection;

/**
 * Lists the session user's passkeys, oldest first, with the RP ID and the user's user handle.
 *
 * The list is every passkey the IdP still accepts for the user, so the page can hand it to the browser as the
 * complete accepted set; passkeys revoked by the user or by the administrator are simply absent.
 *
 * @param deps The database, the issuer, and the clock.
 * @param input The session cookie's value; `undefined` when absent.
 * @returns The passkeys, or `no_session` (absent, malformed, unknown, or expired session) or `user_disabled`.
 * @throws {CorruptRowError} A session, user, or credential row is malformed.
 * @throws {DatabaseError} A read failed.
 */
export async function listOwnPasskeys(
  deps: Pick<PasskeyDeps, "db" | "issuer" | "clock">,
  input: { readonly sessionToken: string | undefined },
): Promise<OwnPasskeysResult> {
  const session = await findActiveSession(deps, input.sessionToken);
  if (session === undefined) return rejected("no_session");
  const enabled = userEnabledCondition(session.userId);
  // One batch is one snapshot, so a user disabled meanwhile cannot get a list with the disabled answer missing.
  const [state, user, rows] = await deps.db.batch([
    { sql: `SELECT ${enabled.sql} AS ok`, params: enabled.params },
    { sql: "SELECT user_handle FROM users WHERE id = ?", params: [session.userId] },
    {
      sql: "SELECT id, created_at, last_used_at, created_via, backup_state FROM credentials WHERE user_id = ? ORDER BY created_at, id",
      params: [session.userId],
    },
  ]);
  const userRow = user?.rows[0];
  if (state?.rows[0]?.["ok"] !== 1 || userRow === undefined) return rejected("user_disabled");
  return {
    kind: "passkeys",
    rpId: deps.issuer.rpId,
    userHandle: base64urlEncode(bytesColumn(userRow, "user_handle")),
    passkeys: (rows?.rows ?? []).map((row) => {
      const createdVia = textColumn(row, "created_via");
      if (createdVia !== "enroll" && createdVia !== "self") throw new CorruptRowError("credentials.created_via is malformed");
      return {
        credential_id: textColumn(row, "id"),
        created_at: integerColumn(row, "created_at"),
        last_used_at: row["last_used_at"] === null ? null : integerColumn(row, "last_used_at"),
        created_via: createdVia,
        backup_state: integerColumn(row, "backup_state") === 1,
      };
    }),
  };
}
