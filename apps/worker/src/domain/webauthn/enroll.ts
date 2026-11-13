// Registration through an enrollment link (docs/design/authentication.md, "パスキーの登録"): /webauthn/register/options
// and /webauthn/register/verify. The challenge is bound to the enrollment token, and the consumption order is fixed by
// the schema: the challenge references the token with ON DELETE CASCADE, so the challenge is consumed first.
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { MAX_PASSKEYS_PER_USER, passkeyBelowLimitCondition, userEnabledCondition } from "@idp/core/passkeys";
import { isRandomTokenFormat } from "@idp/core/identifiers";
import type { PasskeyDeps } from "../deps.js";
import {
  CHALLENGE_LIFETIME_SECONDS,
  allOf,
  bytesColumn,
  challengeStoredCondition,
  condition,
  creationOptions,
  expiredChallengesStatement,
  integerColumn,
  rejected,
  textColumn,
  type CreationOptionsJson,
  type PasskeyRejection,
} from "./ceremony.js";
import { explainRefusal, storePasskeyStatements } from "./registration.js";
import { WebAuthnVerificationError, claimedChallenge, parseRegistrationResponse, verifyRegistration, type RegistrationResponse } from "@idp/webauthn";

/** The result of {@link enrollOptions}. */
export type EnrollOptionsResult = { readonly kind: "options"; readonly options: CreationOptionsJson } | PasskeyRejection;

/** The result of {@link enrollVerify}. */
export type EnrollVerifyResult = { readonly kind: "registered"; readonly credentialId: string } | PasskeyRejection;

const ENROLL_BINDING = "purpose = 'enroll' AND enroll_token_hash = ?";

function tokenLive(tokenHash: string, now: number) {
  return condition("EXISTS (SELECT 1 FROM enroll_tokens WHERE token_hash = ? AND expires_at > ?)", tokenHash, now);
}

/**
 * Handles `/webauthn/register/options`: issues a creation challenge bound to the enrollment token.
 *
 * The token is not consumed here, so reloading the page works until the token expires. The same batch deletes every
 * expired challenge.
 *
 * @param deps The database, issuer, clock, and random source.
 * @param input The token from the link's fragment, untrusted.
 * @returns Creation options (excluding the user's current passkeys), or `invalid_enroll_token`, `user_disabled`, or
 *   `limit_reached`.
 * @throws {CorruptRowError} The user row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function enrollOptions(
  deps: Pick<PasskeyDeps, "db" | "issuer" | "clock" | "random">,
  input: { readonly enrollToken: string },
): Promise<EnrollOptionsResult> {
  if (!isRandomTokenFormat(input.enrollToken)) return rejected("invalid_enroll_token");
  const now = deps.clock.now();
  const tokenHash = await sha256Base64url(input.enrollToken);
  const [tokenRows, credentialRows] = await deps.db.batch([
    {
      sql: `SELECT u.id, u.user_handle, u.name,
                   EXISTS (SELECT 1 FROM user_enablement ue WHERE ue.user_id = u.id AND ue.enablement = 'enabled') AS enabled,
                   (SELECT COUNT(*) FROM credentials c WHERE c.user_id = u.id) AS passkeys
            FROM enroll_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ? AND t.expires_at > ?`,
      params: [tokenHash, now],
    },
    {
      sql: "SELECT id FROM credentials WHERE user_id = (SELECT user_id FROM enroll_tokens WHERE token_hash = ?) ORDER BY created_at, id",
      params: [tokenHash],
    },
  ]);
  const row = tokenRows?.rows[0];
  if (row === undefined) return rejected("invalid_enroll_token");
  if (row["enabled"] !== 1) return rejected("user_disabled");
  if (integerColumn(row, "passkeys") >= MAX_PASSKEYS_PER_USER) return rejected("limit_reached");
  const userId = textColumn(row, "id");

  const challenge = deps.random.token();
  const guard = allOf(userEnabledCondition(userId), passkeyBelowLimitCondition(userId));
  const [, inserted] = await deps.db.batch([
    expiredChallengesStatement(now),
    {
      sql: `INSERT INTO challenges (challenge, purpose, user_id, enroll_token_hash, expires_at)
            SELECT ?, 'enroll', user_id, token_hash, ? FROM enroll_tokens
            WHERE token_hash = ? AND user_id = ? AND expires_at > ? AND ${guard.sql}`,
      params: [challenge, now + CHALLENGE_LIFETIME_SECONDS, tokenHash, userId, now, ...guard.params],
    },
  ]);
  if (inserted?.changes !== 1) return rejected("invalid_enroll_token");
  return {
    kind: "options",
    options: creationOptions(deps, challenge, {
      userHandle: bytesColumn(row, "user_handle"),
      name: textColumn(row, "name"),
      credentialIds: (credentialRows?.rows ?? []).map((r) => textColumn(r, "id")),
    }),
  };
}

/**
 * Handles `/webauthn/register/verify`: verifies the registration and stores the passkey with created_via `enroll`.
 *
 * One batch writes the audit row and the passkey under the same condition (the challenge is still stored for this
 * token, the token is live, the user is enabled and below the limit, and the credential ID is unused), then consumes
 * the challenge and the token in that order. The token is consumed even when the condition fails: it is single-use,
 * and a refused enrollment needs a new link from the administrator.
 *
 * @param deps The database, issuer, clock, random source, and writer version.
 * @param input The token and the parsed JSON body (the `PublicKeyCredential.toJSON()` of the registration).
 * @returns The stored credential ID, or `invalid_enroll_token`, `invalid_request`, `invalid_challenge`,
 *   `verification_failed`, `user_disabled`, `limit_reached`, or `credential_exists`.
 * @throws {DatabaseError} A read or write failed.
 */
export async function enrollVerify(deps: PasskeyDeps, input: { readonly enrollToken: string; readonly credential: unknown }): Promise<EnrollVerifyResult> {
  if (!isRandomTokenFormat(input.enrollToken)) return rejected("invalid_enroll_token");
  let response: RegistrationResponse;
  try {
    response = parseRegistrationResponse(input.credential);
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("invalid_request");
    throw error;
  }
  const challenge = claimedChallenge(response.clientDataJSON);
  const now = deps.clock.now();
  const tokenHash = await sha256Base64url(input.enrollToken);
  const live = tokenLive(tokenHash, now);
  const [tokenRow, challengeRows] = await deps.db.batch([
    { sql: `SELECT user_id FROM enroll_tokens WHERE token_hash = ? AND expires_at > ?`, params: [tokenHash, now] },
    {
      sql: `SELECT user_id FROM challenges WHERE challenge = ? AND ${ENROLL_BINDING} AND expires_at > ?`,
      params: [challenge ?? null, tokenHash, now],
    },
  ]);
  if (tokenRow?.rows[0] === undefined) return rejected("invalid_enroll_token");
  const challengeRow = challengeRows?.rows[0];
  if (challenge === undefined || challengeRow === undefined) return rejected("invalid_challenge");
  const userId = textColumn(challengeRow, "user_id");

  let verified;
  try {
    verified = await verifyRegistration(response, { challenge, rp: deps.issuer });
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) return rejected("verification_failed");
    throw error;
  }

  const passkey = { userId, verified, createdVia: "enroll" } as const;
  const ceremony = allOf(challengeStoredCondition(challenge, ENROLL_BINDING, [tokenHash], now), live);
  const [, inserted] = await deps.db.batch([
    ...storePasskeyStatements(deps, passkey, ceremony),
    { sql: `DELETE FROM challenges WHERE challenge = ? AND ${ENROLL_BINDING}`, params: [challenge, tokenHash] },
    { sql: "DELETE FROM enroll_tokens WHERE token_hash = ?", params: [tokenHash] },
  ]);
  if (inserted?.changes === 1) return { kind: "registered", credentialId: verified.credentialId };
  return rejected(await explainRefusal(deps, passkey));
}
