// What the passkey ceremonies share: the options shapes sent to the browser, the challenge lifetime, the rejection
// reasons, and the reads of a stored credential. The SQL conditions that must hold at write time live with each
// ceremony, because each one binds its challenge to a different issuer (docs/design/data-model.md, challenges).
import { base64urlEncode } from "@idp/base64url";
import type { CoseAlgorithm } from "@idp/cose-key";
import { userEnabledCondition } from "@idp/core/passkeys";
import type { Database, SqlCondition, SqlRow, SqlStatement, SqlValue } from "@idp/core/db";
import { CorruptRowError } from "../clients.js";
import type { PasskeyDeps } from "../deps.js";
import type { StoredCredential } from "@idp/webauthn";

// The algorithms the IdP offers, in the order it prefers them (WebAuthn Level 3 §5.4; docs/design/standards-compliance.md):
// EdDSA over Ed25519, then ES256, then RS256. Each is one @idp/cose-key verifies, so a registered key always verifies.
const OFFERED_COSE_ALGORITHMS: readonly CoseAlgorithm[] = [-8, -7, -257];

/** The `pubKeyCredParams` every creation request offers. */
export const PUB_KEY_CRED_PARAMS: readonly { readonly type: "public-key"; readonly alg: number }[] = OFFERED_COSE_ALGORITHMS.map((alg) => ({
  type: "public-key" as const,
  alg,
}));

/**
 * How long a challenge stays valid: the upper end of the ceremony timeout WebAuthn Level 3 §13.4.3 recommends.
 * The `timeout` of the options is the same, so the browser gives up when the server would.
 */
export const CHALLENGE_LIFETIME_SECONDS = 600;

const CEREMONY_TIMEOUT_MS = CHALLENGE_LIFETIME_SECONDS * 1000;

/** A credential reference in allowCredentials or excludeCredentials (Level 3 §5.10.3). */
export type CredentialDescriptorJson = { readonly type: "public-key"; readonly id: string };

/** `PublicKeyCredentialRequestOptionsJSON` (Level 3 §5.1.9) for `navigator.credentials.get()`. */
export type RequestOptionsJson = {
  readonly challenge: string;
  readonly timeout: number;
  readonly rpId: string;
  /** Empty for the discoverable sign-in, which also serves conditional mediation (§5.1.4). */
  readonly allowCredentials: readonly CredentialDescriptorJson[];
  readonly userVerification: "required";
};

/** `PublicKeyCredentialCreationOptionsJSON` (Level 3 §5.1.8) for `navigator.credentials.create()`. */
export type CreationOptionsJson = {
  readonly rp: { readonly id: string; readonly name: string };
  /** `id` is the 64-byte user handle; `name` and `displayName` are the user's display name, which holds no PII. */
  readonly user: { readonly id: string; readonly name: string; readonly displayName: string };
  readonly challenge: string;
  readonly pubKeyCredParams: readonly { readonly type: "public-key"; readonly alg: number }[];
  readonly timeout: number;
  readonly excludeCredentials: readonly CredentialDescriptorJson[];
  readonly authenticatorSelection: {
    readonly residentKey: "required";
    readonly requireResidentKey: true;
    readonly userVerification: "required";
  };
  readonly attestation: "none";
};

/**
 * Why a ceremony step refused. The HTTP layer maps these to a generic message and an error kind; the user's page
 * never sees internal detail, and none of them is written to the audit log (only success rows are).
 */
export type PasskeyRejectionReason =
  /** The body or a parameter is malformed, or the response could not be parsed. */
  | "invalid_request"
  /** The session cookie is absent, malformed, unknown, or expired. */
  | "no_session"
  /** The sign-in's authorize request cookie is absent, unknown, or expired. */
  | "invalid_authorize_request"
  /** The enrollment token is malformed, unknown, used, or expired. */
  | "invalid_enroll_token"
  /** The challenge is unknown, expired, already used, or bound to another request, token, session, or credential. */
  | "invalid_challenge"
  /** The credential is unknown, or does not belong to the session's user. */
  | "unknown_credential"
  /** The response failed a WebAuthn verification step. */
  | "verification_failed"
  /** The user is disabled (or has no enablement event). */
  | "user_disabled"
  /** The user already has the maximum number of passkeys. */
  | "limit_reached"
  /** The credential ID is already registered, to this user or another. */
  | "credential_exists"
  /** The passkey is the user's last one. */
  | "last_passkey";

/** A refused step. */
export type PasskeyRejection = { readonly kind: "rejected"; readonly reason: PasskeyRejectionReason };

/**
 * Builds a rejection.
 *
 * @param reason Why.
 * @returns The rejection.
 */
export function rejected(reason: PasskeyRejectionReason): PasskeyRejection {
  return { kind: "rejected", reason };
}

/**
 * Builds request options for an assertion with user verification required.
 *
 * @param deps The issuer.
 * @param challenge The stored challenge.
 * @param allowCredentials The credential IDs the assertion may come from; empty for a discoverable sign-in.
 * @returns The options JSON.
 */
export function requestOptions(deps: Pick<PasskeyDeps, "issuer">, challenge: string, allowCredentials: readonly string[]): RequestOptionsJson {
  return {
    challenge,
    timeout: CEREMONY_TIMEOUT_MS,
    rpId: deps.issuer.rpId,
    allowCredentials: allowCredentials.map((id) => ({ type: "public-key", id })),
    userVerification: "required",
  };
}

/** The user a creation request is for. */
export type RegisteringUser = {
  readonly userHandle: Uint8Array;
  readonly name: string;
  /** The user's current credential IDs, excluded so one authenticator is not registered twice. */
  readonly credentialIds: readonly string[];
};

/**
 * Builds creation options for a discoverable credential with user verification and no attestation.
 *
 * @param deps The issuer.
 * @param challenge The stored challenge.
 * @param user The user and their current credentials.
 * @returns The options JSON.
 */
export function creationOptions(deps: Pick<PasskeyDeps, "issuer">, challenge: string, user: RegisteringUser): CreationOptionsJson {
  return {
    rp: { id: deps.issuer.rpId, name: deps.issuer.rpId },
    user: { id: base64urlEncode(user.userHandle), name: user.name, displayName: user.name },
    challenge,
    pubKeyCredParams: PUB_KEY_CRED_PARAMS,
    timeout: CEREMONY_TIMEOUT_MS,
    excludeCredentials: user.credentialIds.map((id) => ({ type: "public-key", id })),
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    attestation: "none",
  };
}

/** Joins conditions with AND, keeping their parameters in order. */
export function allOf(...conditions: readonly SqlCondition[]): SqlCondition {
  return { sql: conditions.map((c) => `(${c.sql})`).join(" AND "), params: conditions.flatMap((c) => c.params) };
}

/** A condition from SQL and parameters, for the ad hoc parts of a guard. */
export function condition(sql: string, ...params: readonly SqlValue[]): SqlCondition {
  return { sql, params };
}

/** The guard that the challenge is still stored with exactly this binding and has not expired. */
export function challengeStoredCondition(challenge: string, binding: string, bindingParams: readonly SqlValue[], now: number): SqlCondition {
  return {
    sql: `EXISTS (SELECT 1 FROM challenges WHERE challenge = ? AND ${binding} AND expires_at > ?)`,
    params: [challenge, ...bindingParams, now],
  };
}

/** A stored credential with its owner, as an assertion is verified against it. */
export type CredentialRecord = StoredCredential & { readonly id: string; readonly userId: string };

/** The SELECT that {@link parseCredentialRecord} reads, by credential ID. */
export const CREDENTIAL_RECORD_SQL = `SELECT c.id, c.user_id, c.public_key, c.sign_count, c.backup_eligible, u.user_handle
  FROM credentials c JOIN users u ON u.id = c.user_id WHERE c.id = ?`;

function column<T>(row: SqlRow, name: string, check: (value: unknown) => value is T): T {
  const value = row[name];
  if (!check(value)) throw new CorruptRowError(`${name} is malformed`);
  return value;
}

function isText(value: unknown): value is string {
  return typeof value === "string";
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/**
 * Reads a row of {@link CREDENTIAL_RECORD_SQL}.
 *
 * @param row The row.
 * @returns The record.
 * @throws {CorruptRowError} A column does not have the schema's type.
 */
export function parseCredentialRecord(row: SqlRow): CredentialRecord {
  return {
    id: column(row, "id", isText),
    userId: column(row, "user_id", isText),
    publicKey: column(row, "public_key", isBytes),
    signCount: column(row, "sign_count", isInteger),
    backupEligible: column(row, "backup_eligible", isInteger) === 1,
    userHandle: column(row, "user_handle", isBytes),
  };
}

/** Reads a text column, rejecting corruption. */
export function textColumn(row: SqlRow, name: string): string {
  return column(row, name, isText);
}

/** Reads a byte column, rejecting corruption. */
export function bytesColumn(row: SqlRow, name: string): Uint8Array {
  return column(row, name, isBytes);
}

/** Reads an integer column, rejecting corruption. */
export function integerColumn(row: SqlRow, name: string): number {
  return column(row, name, isInteger);
}

/**
 * The guard that a credential still has the state an assertion was verified against: the same owner and the same
 * sign count. A concurrent ceremony with the same credential that already moved the counter makes the write fail
 * instead of letting a second, older counter value through.
 */
export function credentialUnchangedCondition(record: CredentialRecord): SqlCondition {
  return condition("EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ? AND sign_count = ?)", record.id, record.userId, record.signCount);
}

/**
 * The update after a verified assertion (Level 3 §7.2 step 25; docs/design/data-model.md: every ceremony that
 * verifies a signature updates sign_count and last_used_at in the same batch).
 *
 * @param record The credential as read.
 * @param verified The new sign count and backup state.
 * @param now The current time.
 * @param guard The ceremony's write condition.
 * @returns The UPDATE statement.
 */
export function credentialUsedStatement(
  record: CredentialRecord,
  verified: { readonly signCount: number; readonly backupState: boolean },
  now: number,
  guard: SqlCondition,
): SqlStatement {
  return {
    sql: `UPDATE credentials SET sign_count = ?, backup_state = ?, last_used_at = ? WHERE id = ? AND ${guard.sql}`,
    params: [verified.signCount, verified.backupState ? 1 : 0, now, record.id, ...guard.params],
  };
}

/**
 * Reads whether a user is enabled now, only to explain a write its guard refused; the refusal itself always comes
 * from the guard in the write statement.
 *
 * @param db The database.
 * @param userId The user.
 * @returns Whether user_enablement says `enabled`.
 * @throws {DatabaseError} The read failed.
 */
export async function isUserEnabled(db: Database, userId: string): Promise<boolean> {
  const enabled = userEnabledCondition(userId);
  const [result] = await db.batch([{ sql: `SELECT ${enabled.sql} AS ok`, params: enabled.params }]);
  return result?.rows[0]?.["ok"] === 1;
}

/** Deletes the expired challenges of every purpose; issuing a new one runs it in the same batch (data-model.md). */
export function expiredChallengesStatement(now: number): SqlStatement {
  return { sql: "DELETE FROM challenges WHERE expires_at <= ?", params: [now] };
}
