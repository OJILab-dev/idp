// The passkey sign-in (docs/design/authentication.md, sign-in steps 4 and 5): /webauthn/auth/options and
// /webauthn/auth/verify. The challenge is bound to the authorize request in the browser's __Host- cookie, because a
// discoverable credential leaves the user unknown until the assertion arrives. A verified sign-in creates the session
// that /authorize/resume (authorize.ts) then turns into a code.
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isRandomTokenFormat, userEnabledCondition, type SqlCondition } from "../../shared/index.js";
import type { PasskeyDeps } from "../deps.js";
import { SESSION_LIFETIME_SECONDS } from "../sessions.js";
import {
  CHALLENGE_LIFETIME_SECONDS,
  CREDENTIAL_RECORD_SQL,
  allOf,
  challengeStoredCondition,
  condition,
  credentialUnchangedCondition,
  credentialUsedStatement,
  expiredChallengesStatement,
  isUserEnabled,
  parseCredentialRecord,
  rejected,
  requestOptions,
  type PasskeyRejection,
  type RequestOptionsJson,
} from "./ceremony.js";
import {
  WebAuthnVerificationError,
  claimedChallenge,
  parseAuthenticationResponse,
  verifyAuthentication,
  type AuthenticationResponse,
} from "./verify.js";

/** The result of {@link signInOptions}. */
export type SignInOptionsResult = { readonly kind: "options"; readonly options: RequestOptionsJson } | PasskeyRejection;

/** The result of {@link signInVerify}. */
export type SignInVerifyResult =
  | {
      readonly kind: "signed_in";
      /** The plaintext session token for the session cookie; only its hash is stored. */
      readonly sessionToken: string;
      /** When the session ends, in UNIX seconds; the cookie should not outlive it. */
      readonly expiresAt: number;
    }
  | PasskeyRejection;

/** A request to `/webauthn/auth/verify`. */
export type SignInVerifyInput = {
  /** The authorize request cookie's value; `undefined` when absent. */
  readonly authorizeRequestId: string | undefined;
  /** The current session cookie's value, replaced on success; `undefined` when absent. */
  readonly sessionToken: string | undefined;
  /** The parsed JSON body: the `PublicKeyCredential.toJSON()` of the assertion. */
  readonly credential: unknown;
};

const SIGN_IN_BINDING = "purpose = 'sign_in' AND authorize_request_id_hash = ?";

function authorizeRequestLive(idHash: string, now: number): SqlCondition {
  return condition("EXISTS (SELECT 1 FROM authorize_requests WHERE id_hash = ? AND expires_at > ?)", idHash, now);
}

/**
 * Handles `/webauthn/auth/options`: issues one sign-in challenge bound to the browser's authorize request.
 *
 * The sign-in page calls it on every load; that write before authentication is the accepted cost of
 * docs/design/free-tier.md. The same batch deletes every expired challenge.
 *
 * @param deps The database, issuer, clock, and random source.
 * @param input The authorize request cookie's value; `undefined` when absent.
 * @returns Request options with an empty allowCredentials (discoverable credentials, which also serve conditional
 *   mediation), or `invalid_authorize_request` when the cookie is absent, malformed, unknown, or expired.
 * @throws {DatabaseError} The write failed.
 */
export async function signInOptions(
  deps: Pick<PasskeyDeps, "db" | "issuer" | "clock" | "random">,
  input: { readonly authorizeRequestId: string | undefined },
): Promise<SignInOptionsResult> {
  if (input.authorizeRequestId === undefined || !isRandomTokenFormat(input.authorizeRequestId)) {
    return rejected("invalid_authorize_request");
  }
  const now = deps.clock.now();
  const idHash = await sha256Base64url(input.authorizeRequestId);
  const challenge = deps.random.token();
  const [, inserted] = await deps.db.batch([
    expiredChallengesStatement(now),
    {
      sql: `INSERT INTO challenges (challenge, purpose, authorize_request_id_hash, expires_at)
            SELECT ?, 'sign_in', id_hash, ? FROM authorize_requests WHERE id_hash = ? AND expires_at > ?`,
      params: [challenge, now + CHALLENGE_LIFETIME_SECONDS, idHash, now],
    },
  ]);
  if (inserted?.changes !== 1) return rejected("invalid_authorize_request");
  return { kind: "options", options: requestOptions(deps, challenge, []) };
}

/**
 * Handles `/webauthn/auth/verify`: verifies the assertion and creates a new session bound to the credential.
 *
 * The session insert carries every condition in its own statement (the challenge is still stored for this authorize
 * request, the request has not expired, the user is enabled, and the credential's counter is the one verified), so a
 * replay, a concurrent sign-in with the same challenge, or a `user_disable` between the read and the write leaves no
 * session. The same batch consumes the challenge, replaces the browser's previous session, updates the credential's
 * sign count and last use, and deletes expired sessions. The authorize request is left for `/authorize/resume`.
 *
 * @param deps The database, issuer, clock, and random source.
 * @param input The cookies and the assertion.
 * @returns The new session, or a rejection: `invalid_authorize_request`, `invalid_request` (unparsable assertion),
 *   `invalid_challenge`, `unknown_credential`, `verification_failed`, or `user_disabled`.
 * @throws {CorruptRowError} The credential row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function signInVerify(deps: Pick<PasskeyDeps, "db" | "issuer" | "clock" | "random">, input: SignInVerifyInput): Promise<SignInVerifyResult> {
  if (input.authorizeRequestId === undefined || !isRandomTokenFormat(input.authorizeRequestId)) {
    return rejected("invalid_authorize_request");
  }
  let response: AuthenticationResponse;
  try {
    response = parseAuthenticationResponse(input.credential);
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("invalid_request");
    throw error;
  }
  const challenge = claimedChallenge(response.clientDataJSON);
  if (challenge === undefined) return rejected("invalid_challenge");

  const now = deps.clock.now();
  const idHash = await sha256Base64url(input.authorizeRequestId);
  const challengeStored = allOf(challengeStoredCondition(challenge, SIGN_IN_BINDING, [idHash], now), authorizeRequestLive(idHash, now));
  const [found, credentialRows] = await deps.db.batch([
    { sql: `SELECT ${challengeStored.sql} AS ok`, params: challengeStored.params },
    { sql: CREDENTIAL_RECORD_SQL, params: [response.credentialId] },
  ]);
  if (found?.rows[0]?.["ok"] !== 1) return rejected("invalid_challenge");
  const row = credentialRows?.rows[0];
  if (row === undefined) return rejected("unknown_credential");
  const credential = parseCredentialRecord(row);

  let verified;
  try {
    verified = await verifyAuthentication(response, { challenge, rp: deps.issuer, credential, userHandleRequired: true });
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("verification_failed");
    throw error;
  }

  const sessionToken = deps.random.token();
  const expiresAt = now + SESSION_LIFETIME_SECONDS;
  const enabled = userEnabledCondition(credential.userId);
  const guard = allOf(challengeStored, enabled, credentialUnchangedCondition(credential));
  const oldSessionHash = input.sessionToken !== undefined && isRandomTokenFormat(input.sessionToken) ? await sha256Base64url(input.sessionToken) : null;
  // The session insert runs before the credential update, whose new counter would otherwise fail the guard.
  const [, , inserted] = await deps.db.batch([
    { sql: "DELETE FROM sessions WHERE expires_at <= ?", params: [now] },
    { sql: `DELETE FROM sessions WHERE token_hash = ? AND ${guard.sql}`, params: [oldSessionHash, ...guard.params] },
    {
      sql: `INSERT INTO sessions (token_hash, user_id, credential_id, auth_time, expires_at) SELECT ?, ?, ?, ?, ? WHERE ${guard.sql}`,
      params: [await sha256Base64url(sessionToken), credential.userId, credential.id, now, expiresAt, ...guard.params],
    },
    credentialUsedStatement(credential, verified, now, guard),
    { sql: `DELETE FROM challenges WHERE challenge = ? AND ${SIGN_IN_BINDING}`, params: [challenge, idHash] },
  ]);
  if (inserted?.changes === 1) return { kind: "signed_in", sessionToken, expiresAt };
  return rejected(await isUserEnabled(deps.db, credential.userId) ? "invalid_challenge" : "user_disabled");
}

