// The account page's own passkey operations (docs/design/authentication.md, "本人によるパスキーの追加" and "本人による
// パスキーの失効"): /webauthn/add/begin|options|verify and /webauthn/revoke/begin|verify. A session cookie alone is
// never enough: each operation first re-authenticates with UV by one of the same user's passkeys (NIST SP 800-63B-4
// §4.1.2.1), and every challenge stays bound to the session (and, for a revocation, to the target credential).
// The Sec-Fetch-Site / Origin check belongs to the HTTP layer.
import {
  MAX_PASSKEYS_PER_USER,
  passkeyBelowLimitCondition,
  passkeyRevocableCondition,
  userEnabledCondition,
} from "@idp/core/passkeys";
import { auditSuccessStatement } from "@idp/core/audit";
import { isCredentialId } from "@idp/core/identifiers";
import type { SqlCondition, SqlValue } from "@idp/core/db";
import type { PasskeyDeps } from "../deps.js";
import { findActiveSession, type ActiveSession } from "../sessions.js";
import {
  CHALLENGE_LIFETIME_SECONDS,
  CREDENTIAL_RECORD_SQL,
  allOf,
  bytesColumn,
  challengeStoredCondition,
  condition,
  creationOptions,
  credentialUnchangedCondition,
  credentialUsedStatement,
  expiredChallengesStatement,
  isUserEnabled,
  parseCredentialRecord,
  rejected,
  requestOptions,
  textColumn,
  type CreationOptionsJson,
  type CredentialRecord,
  type PasskeyRejection,
  type RequestOptionsJson,
} from "./ceremony.js";
import { explainRefusal, storePasskeyStatements } from "./registration.js";
import {
  WebAuthnVerificationError,
  claimedChallenge,
  parseAuthenticationResponse,
  parseRegistrationResponse,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationResponse,
  type RegistrationResponse,
  type VerifiedAuthentication,
} from "@idp/webauthn";

/** The result of {@link addBegin} and {@link revokeBegin}: request options for the re-authentication. */
export type ReauthOptionsResult = { readonly kind: "options"; readonly options: RequestOptionsJson } | PasskeyRejection;

/** The result of {@link addOptions}: creation options for the new passkey. */
export type AddOptionsResult = { readonly kind: "options"; readonly options: CreationOptionsJson } | PasskeyRejection;

/** The result of {@link addVerify}. */
export type AddVerifyResult = { readonly kind: "registered"; readonly credentialId: string } | PasskeyRejection;

/** The result of {@link revokeVerify}. */
export type RevokeVerifyResult =
  | {
      readonly kind: "revoked";
      /** The current session was signed in with the revoked passkey, so it ended too; the page says so. */
      readonly sessionEnded: boolean;
    }
  | PasskeyRejection;

type Deps = PasskeyDeps;

// The session's user as one snapshot: enabled, their display data, and their passkeys.
type SessionUser = {
  readonly session: ActiveSession;
  readonly userHandle: Uint8Array;
  readonly name: string;
  readonly credentialIds: readonly string[];
};

async function loadSessionUser(deps: Deps, sessionToken: string | undefined): Promise<SessionUser | PasskeyRejection> {
  const session = await findActiveSession(deps, sessionToken);
  if (session === undefined) return rejected("no_session");
  const enabled = userEnabledCondition(session.userId);
  const [userRows, credentialRows] = await deps.db.batch([
    { sql: `SELECT user_handle, name, ${enabled.sql} AS enabled FROM users WHERE id = ?`, params: [...enabled.params, session.userId] },
    { sql: "SELECT id FROM credentials WHERE user_id = ? ORDER BY created_at, id", params: [session.userId] },
  ]);
  const user = userRows?.rows[0];
  if (user?.["enabled"] !== 1) return rejected("user_disabled");
  return {
    session,
    userHandle: bytesColumn(user, "user_handle"),
    name: textColumn(user, "name"),
    credentialIds: (credentialRows?.rows ?? []).map((r) => textColumn(r, "id")),
  };
}

function isRejection(value: object): value is PasskeyRejection {
  return "kind" in value && value.kind === "rejected";
}

// The session is still live and still the same user's; every write of these ceremonies carries it.
function sessionLive(session: ActiveSession, now: number): SqlCondition {
  return condition("EXISTS (SELECT 1 FROM sessions WHERE token_hash = ? AND user_id = ? AND expires_at > ?)", session.tokenHash, session.userId, now);
}

type Binding = { readonly sql: string; readonly params: readonly SqlValue[] };

function bindingFor(su: SessionUser, purpose: "add_reauth" | "add_register" | "revoke", target?: string): Binding {
  const base = { sql: `purpose = '${purpose}' AND session_token_hash = ? AND user_id = ?`, params: [su.session.tokenHash, su.session.userId] };
  return target === undefined ? base : { sql: `${base.sql} AND target_credential_id = ?`, params: [...base.params, target] };
}

async function issueChallenge(
  deps: Deps,
  su: SessionUser,
  purpose: "add_reauth" | "revoke",
  target?: string,
): Promise<string | undefined> {
  const now = deps.clock.now();
  const challenge = deps.random.token();
  const guard = allOf(sessionLive(su.session, now), userEnabledCondition(su.session.userId));
  const [, inserted] = await deps.db.batch([
    expiredChallengesStatement(now),
    {
      sql: `INSERT INTO challenges (challenge, purpose, user_id, session_token_hash, target_credential_id, expires_at)
            SELECT ?, ?, ?, ?, ?, ? WHERE ${guard.sql}
              AND (? IS NULL OR EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ?))`,
      params: [
        challenge,
        purpose,
        su.session.userId,
        su.session.tokenHash,
        target ?? null,
        now + CHALLENGE_LIFETIME_SECONDS,
        ...guard.params,
        target ?? null,
        target ?? null,
        su.session.userId,
      ],
    },
  ]);
  return inserted?.changes === 1 ? challenge : undefined;
}

type Reauthenticated = {
  readonly challenge: string;
  readonly record: CredentialRecord;
  readonly verified: VerifiedAuthentication;
  /** The challenge is still stored with its binding and the session is live: the guard of every write that follows. */
  readonly guard: SqlCondition;
  readonly binding: Binding;
};

// The UV assertion that must precede an add or a revocation: by a passkey of the session's own user, against a
// challenge bound to this session (and target).
async function reauthenticate(deps: Deps, su: SessionUser, body: unknown, binding: Binding): Promise<Reauthenticated | PasskeyRejection> {
  let response: AuthenticationResponse;
  try {
    response = parseAuthenticationResponse(body);
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("invalid_request");
    throw error;
  }
  const challenge = claimedChallenge(response.clientDataJSON);
  if (challenge === undefined) return rejected("invalid_challenge");
  const now = deps.clock.now();
  const stored = allOf(challengeStoredCondition(challenge, binding.sql, binding.params, now), sessionLive(su.session, now));
  const [found, credentialRows] = await deps.db.batch([
    { sql: `SELECT ${stored.sql} AS ok`, params: stored.params },
    { sql: CREDENTIAL_RECORD_SQL, params: [response.credentialId] },
  ]);
  if (found?.rows[0]?.["ok"] !== 1) return rejected("invalid_challenge");
  const row = credentialRows?.rows[0];
  const record = row === undefined ? undefined : parseCredentialRecord(row);
  if (record === undefined || record.userId !== su.session.userId) return rejected("unknown_credential");
  try {
    const verified = await verifyAuthentication(response, { challenge, rp: deps.issuer, credential: record, userHandleRequired: false });
    const guard = allOf(stored, userEnabledCondition(record.userId), credentialUnchangedCondition(record));
    return { challenge, record, verified, guard, binding };
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("verification_failed");
    throw error;
  }
}

function consumeStatement(reauth: Pick<Reauthenticated, "challenge" | "binding">): { readonly sql: string; readonly params: readonly SqlValue[] } {
  return { sql: `DELETE FROM challenges WHERE challenge = ? AND ${reauth.binding.sql}`, params: [reauth.challenge, ...reauth.binding.params] };
}

/**
 * Handles `/webauthn/add/begin`: issues the re-authentication challenge for adding a passkey.
 *
 * @param deps The passkey dependencies.
 * @param input The session cookie's value; `undefined` when absent.
 * @returns Request options allowing only the user's own passkeys, or `no_session`, `user_disabled`, or
 *   `limit_reached`.
 * @throws {CorruptRowError} A session, user, or credential row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function addBegin(deps: Deps, input: { readonly sessionToken: string | undefined }): Promise<ReauthOptionsResult> {
  const su = await loadSessionUser(deps, input.sessionToken);
  if (isRejection(su)) return su;
  if (su.credentialIds.length >= MAX_PASSKEYS_PER_USER) return rejected("limit_reached");
  const challenge = await issueChallenge(deps, su, "add_reauth");
  // The read above saw a live session and an enabled user; a refused insert means one changed in between.
  if (challenge === undefined) return rejected((await isUserEnabled(deps.db, su.session.userId)) ? "no_session" : "user_disabled");
  return { kind: "options", options: requestOptions(deps, challenge, su.credentialIds) };
}

/**
 * Handles `/webauthn/add/options`: verifies the re-authentication and issues the registration challenge.
 *
 * One batch issues the registration challenge under the re-authentication's condition (its challenge is still bound
 * to this session, the session is live, the user is enabled and below the limit, and the signing passkey's counter is
 * the one verified), updates the signing passkey's sign count and last use, and consumes the re-authentication
 * challenge.
 *
 * @param deps The passkey dependencies.
 * @param input The session cookie's value and the assertion.
 * @returns Creation options excluding the user's passkeys, or `no_session`, `user_disabled`, `invalid_request`,
 *   `invalid_challenge`, `unknown_credential` (the passkey is not the session user's), `verification_failed`, or
 *   `limit_reached`.
 * @throws {CorruptRowError} A row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function addOptions(deps: Deps, input: { readonly sessionToken: string | undefined; readonly credential: unknown }): Promise<AddOptionsResult> {
  const su = await loadSessionUser(deps, input.sessionToken);
  if (isRejection(su)) return su;
  const reauth = await reauthenticate(deps, su, input.credential, bindingFor(su, "add_reauth"));
  if (isRejection(reauth)) return reauth;
  if (su.credentialIds.length >= MAX_PASSKEYS_PER_USER) return rejected("limit_reached");

  const now = deps.clock.now();
  const challenge = deps.random.token();
  const guard = allOf(reauth.guard, passkeyBelowLimitCondition(su.session.userId));
  const [, inserted] = await deps.db.batch([
    expiredChallengesStatement(now),
    {
      sql: `INSERT INTO challenges (challenge, purpose, user_id, session_token_hash, expires_at)
            SELECT ?, 'add_register', ?, ?, ? WHERE ${guard.sql}`,
      params: [challenge, su.session.userId, su.session.tokenHash, now + CHALLENGE_LIFETIME_SECONDS, ...guard.params],
    },
    credentialUsedStatement(reauth.record, reauth.verified, now, reauth.guard),
    consumeStatement(reauth),
  ]);
  if (inserted?.changes !== 1) return rejected(await explainUserState(deps, su.session.userId, "invalid_challenge"));
  return { kind: "options", options: creationOptions(deps, challenge, su) };
}

/**
 * Handles `/webauthn/add/verify`: verifies the registration and stores the passkey with created_via `self`.
 *
 * Only a registration challenge issued by {@link addOptions} to this session is accepted, so the re-authentication
 * cannot be skipped. The audit row (`passkey_add`) and the insert carry the same condition in the same batch.
 *
 * @param deps The passkey dependencies.
 * @param input The session cookie's value and the registration.
 * @returns The stored credential ID, or `no_session`, `user_disabled`, `invalid_request`, `invalid_challenge`,
 *   `verification_failed`, `limit_reached`, or `credential_exists`.
 * @throws {CorruptRowError} A row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function addVerify(deps: Deps, input: { readonly sessionToken: string | undefined; readonly credential: unknown }): Promise<AddVerifyResult> {
  const su = await loadSessionUser(deps, input.sessionToken);
  if (isRejection(su)) return su;
  let response: RegistrationResponse;
  try {
    response = parseRegistrationResponse(input.credential);
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("invalid_request");
    throw error;
  }
  const challenge = claimedChallenge(response.clientDataJSON);
  if (challenge === undefined) return rejected("invalid_challenge");
  const now = deps.clock.now();
  const binding = bindingFor(su, "add_register");
  const stored = allOf(challengeStoredCondition(challenge, binding.sql, binding.params, now), sessionLive(su.session, now));
  const [found] = await deps.db.batch([{ sql: `SELECT ${stored.sql} AS ok`, params: stored.params }]);
  if (found?.rows[0]?.["ok"] !== 1) return rejected("invalid_challenge");

  let verified;
  try {
    verified = await verifyRegistration(response, { challenge, rp: deps.issuer });
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("verification_failed");
    throw error;
  }
  const passkey = { userId: su.session.userId, verified, createdVia: "self" } as const;
  const [, inserted] = await deps.db.batch([...storePasskeyStatements(deps, passkey, stored), consumeStatement({ challenge, binding })]);
  if (inserted?.changes === 1) return { kind: "registered", credentialId: verified.credentialId };
  return rejected(await explainRefusal(deps, passkey));
}

/**
 * Handles `/webauthn/revoke/begin`: issues the re-authentication challenge for revoking one of the user's passkeys,
 * bound to the session and to that credential.
 *
 * @param deps The passkey dependencies.
 * @param input The session cookie's value and the credential ID to revoke.
 * @returns Request options allowing the user's passkeys (the target included), or `no_session`, `user_disabled`,
 *   `invalid_request` (malformed credential ID), `unknown_credential` (not the user's), or `last_passkey`.
 * @throws {CorruptRowError} A row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function revokeBegin(
  deps: Deps,
  input: { readonly sessionToken: string | undefined; readonly credentialId: string },
): Promise<ReauthOptionsResult> {
  if (!isCredentialId(input.credentialId)) return rejected("invalid_request");
  const su = await loadSessionUser(deps, input.sessionToken);
  if (isRejection(su)) return su;
  if (!su.credentialIds.includes(input.credentialId)) return rejected("unknown_credential");
  if (su.credentialIds.length < 2) return rejected("last_passkey");
  const challenge = await issueChallenge(deps, su, "revoke", input.credentialId);
  if (challenge === undefined) {
    if (!(await isUserEnabled(deps.db, su.session.userId))) return rejected("user_disabled");
    return rejected((await findActiveSession(deps, input.sessionToken)) === undefined ? "no_session" : "unknown_credential");
  }
  return { kind: "options", options: requestOptions(deps, challenge, su.credentialIds) };
}

/**
 * Handles `/webauthn/revoke/verify`: verifies the re-authentication and deletes the passkey.
 *
 * The batch writes the `passkey_self_revoke` audit row under the re-authentication's condition and the revocable rule
 * (the target is the user's and not their last passkey, checked in the statement itself), updates the signing
 * passkey, consumes the challenge, and then deletes the target. The challenge references the target with ON DELETE
 * CASCADE, so it must be consumed before the delete; the delete therefore cannot test the challenge any more, and
 * tests the audit row written by this batch instead (see {@link thisBatchRevocationAudited}). Deleting the passkey
 * cascades to the sessions signed in with it and their unused codes.
 *
 * @param deps The passkey dependencies.
 * @param input The session cookie's value, the credential ID to revoke, and the assertion.
 * @returns Whether the current session ended with it, or `no_session`, `user_disabled`, `invalid_request`,
 *   `invalid_challenge` (including a challenge issued for another credential ID), `unknown_credential`,
 *   `verification_failed`, or `last_passkey`.
 * @throws {CorruptRowError} A row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function revokeVerify(
  deps: Deps,
  input: { readonly sessionToken: string | undefined; readonly credentialId: string; readonly credential: unknown },
): Promise<RevokeVerifyResult> {
  if (!isCredentialId(input.credentialId)) return rejected("invalid_request");
  const su = await loadSessionUser(deps, input.sessionToken);
  if (isRejection(su)) return su;
  const reauth = await reauthenticate(deps, su, input.credential, bindingFor(su, "revoke", input.credentialId));
  if (isRejection(reauth)) return reauth;

  const now = deps.clock.now();
  const userId = su.session.userId;
  const target = `user:${userId}` as const;
  const detail = { credential_id: input.credentialId };
  const revocable = allOf(passkeyRevocableCondition(userId, input.credentialId), userEnabledCondition(userId));
  const audited = thisBatchRevocationAudited(target, detail);
  const [, , , deleted] = await deps.db.batch([
    auditSuccessStatement({
      occurredAt: now,
      actor: { kind: "user" },
      writerVersion: deps.writerVersion,
      operation: "passkey_self_revoke",
      target,
      detail,
      guard: allOf(reauth.guard, revocable),
    }),
    credentialUsedStatement(reauth.record, reauth.verified, now, reauth.guard),
    consumeStatement(reauth),
    {
      // RETURNING, not the change count: D1's count includes the rows the foreign keys cascade to.
      sql: `DELETE FROM credentials WHERE id = ? AND user_id = ? AND ${revocable.sql} AND ${audited.sql} RETURNING id`,
      params: [input.credentialId, userId, ...revocable.params, ...audited.params],
    },
  ]);
  if (deleted?.rows.length === 1) return { kind: "revoked", sessionEnded: su.session.credentialId === input.credentialId };
  return rejected(await explainRevocationRefusal(deps, userId, input.credentialId));
}

/**
 * The newest audit row is this batch's `passkey_self_revoke` of the credential.
 *
 * Sound without a token of its own: a batch is one transaction, so nothing else writes between this batch's audit
 * insert and its delete. If this batch's insert did not happen, the newest row would have to be an earlier
 * self-revocation of the same credential, which deleted it in its own batch; the credential can only exist again
 * through an enrollment or an add, and both write a newer audit row (`passkey_enroll` or `passkey_add`). So while the
 * credential exists, a newest row of this shape can only be this batch's.
 */
function thisBatchRevocationAudited(target: string, detail: { readonly credential_id: string }): SqlCondition {
  return condition(
    `EXISTS (SELECT 1 FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log) AND actor = 'user' AND result = 'success'
       AND operation = 'passkey_self_revoke' AND target = ? AND detail_json = ?)`,
    target,
    JSON.stringify(detail),
  );
}

async function explainUserState(deps: Deps, userId: string, otherwise: "invalid_challenge"): Promise<"user_disabled" | "limit_reached" | "invalid_challenge"> {
  const enabled = userEnabledCondition(userId);
  const below = passkeyBelowLimitCondition(userId);
  const [result] = await deps.db.batch([
    { sql: `SELECT ${enabled.sql} AS enabled, ${below.sql} AS below`, params: [...enabled.params, ...below.params] },
  ]);
  if (result?.rows[0]?.["enabled"] !== 1) return "user_disabled";
  if (result.rows[0]["below"] !== 1) return "limit_reached";
  return otherwise;
}

async function explainRevocationRefusal(
  deps: Deps,
  userId: string,
  credentialId: string,
): Promise<"user_disabled" | "unknown_credential" | "last_passkey" | "invalid_challenge"> {
  const enabled = userEnabledCondition(userId);
  const [result] = await deps.db.batch([
    {
      sql: `SELECT ${enabled.sql} AS enabled, EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ?) AS owned,
                   (SELECT COUNT(*) FROM credentials WHERE user_id = ?) AS passkeys`,
      params: [...enabled.params, credentialId, userId, userId],
    },
  ]);
  const row = result?.rows[0];
  if (row?.["enabled"] !== 1) return "user_disabled";
  if (row["owned"] !== 1) return "unknown_credential";
  if ((row["passkeys"] as number) < 2) return "last_passkey";
  return "invalid_challenge";
}
