// Storing a verified new passkey, shared by the enrollment link and the self-service add. Both bind under the same
// rules (docs/design/authentication.md): the user is enabled, is below the passkey limit, and the credential ID is
// not registered to anyone. Each rule is a condition of the INSERT itself, and the audit row carries the same
// condition in the statement before it, so the row exists exactly when the passkey was stored.
import {
  auditSuccessStatement,
  passkeyBelowLimitCondition,
  userEnabledCondition,
  type SqlCondition,
  type SqlStatement,
} from "../../shared/index.js";
import type { PasskeyDeps } from "../deps.js";
import { allOf, condition } from "./ceremony.js";
import type { VerifiedRegistration } from "@idp/webauthn";

/** The registration and where it came from. */
export type NewPasskey = {
  readonly userId: string;
  readonly verified: VerifiedRegistration;
  readonly createdVia: "enroll" | "self";
};

/**
 * The guard every binding path shares.
 *
 * @param passkey The passkey to store.
 * @returns The user is enabled, below the limit, and the credential ID is unused (Level 3 §7.1 step 26).
 */
export function bindableCondition(passkey: NewPasskey): SqlCondition {
  return allOf(
    userEnabledCondition(passkey.userId),
    passkeyBelowLimitCondition(passkey.userId),
    condition("NOT EXISTS (SELECT 1 FROM credentials WHERE id = ?)", passkey.verified.credentialId),
  );
}

/**
 * Builds the audit row and the insert, both guarded by the ceremony's own condition and {@link bindableCondition}.
 * The audit row goes first: after the insert, the limit and the unused-ID conditions would no longer hold.
 *
 * @param deps The clock and the writer version.
 * @param passkey The passkey to store.
 * @param ceremony The ceremony's binding condition (its challenge is still stored, its token or session is live).
 * @returns The two statements, in batch order; the INSERT is the second.
 * @throws {InvalidAuditRowError} The credential ID or user ID does not have the contract's format.
 */
export function storePasskeyStatements(
  deps: Pick<PasskeyDeps, "clock" | "writerVersion">,
  passkey: NewPasskey,
  ceremony: SqlCondition,
): readonly [SqlStatement, SqlStatement] {
  const now = deps.clock.now();
  const guard = allOf(ceremony, bindableCondition(passkey));
  const { verified } = passkey;
  return [
    auditSuccessStatement({
      occurredAt: now,
      actor: { kind: "user" },
      writerVersion: deps.writerVersion,
      operation: passkey.createdVia === "enroll" ? "passkey_enroll" : "passkey_add",
      target: `user:${passkey.userId}`,
      detail: { credential_id: verified.credentialId },
      guard,
    }),
    {
      sql: `INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via)
            SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${guard.sql}`,
      params: [
        verified.credentialId,
        passkey.userId,
        verified.publicKey,
        verified.signCount,
        verified.backupEligible ? 1 : 0,
        verified.backupState ? 1 : 0,
        now,
        passkey.createdVia,
        ...guard.params,
      ],
    },
  ];
}

/** Why a guarded insert did not happen, read afterwards only to report it. */
export type BindRefusal = "user_disabled" | "limit_reached" | "credential_exists" | "invalid_challenge";

/**
 * Explains a refused insert. The refusal itself came from the guard; this read only names a reason.
 *
 * @param deps The database.
 * @param passkey The passkey that was not stored.
 * @returns The first rule that fails now, or `invalid_challenge` when all hold (the challenge was consumed meanwhile).
 * @throws {DatabaseError} The read failed.
 */
export async function explainRefusal(deps: Pick<PasskeyDeps, "db">, passkey: NewPasskey): Promise<BindRefusal> {
  const enabled = userEnabledCondition(passkey.userId);
  const below = passkeyBelowLimitCondition(passkey.userId);
  const [result] = await deps.db.batch([
    {
      sql: `SELECT ${enabled.sql} AS enabled, ${below.sql} AS below, EXISTS (SELECT 1 FROM credentials WHERE id = ?) AS taken`,
      params: [...enabled.params, ...below.params, passkey.verified.credentialId],
    },
  ]);
  const row = result?.rows[0];
  if (row?.["enabled"] !== 1) return "user_disabled";
  if (row["taken"] === 1) return "credential_exists";
  if (row["below"] !== 1) return "limit_reached";
  return "invalid_challenge";
}
