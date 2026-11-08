// The passkey rules both Workers enforce (docs/design/authentication.md, docs/design/idpctl.md): the per-user limit
// and "the last passkey cannot be revoked". Each is a SQL condition meant for the WHERE of the very statement that
// inserts or deletes the credential, so two concurrent ceremonies cannot both pass a check made earlier.
import type { SqlCondition } from "./audit.js";
import { MAX_PASSKEYS_PER_USER } from "./limits.js";

function passkeyCount(): string {
  return "(SELECT COUNT(*) FROM credentials WHERE user_id = ?)";
}

/**
 * The user exists and is enabled now; a user without any enablement event is disabled (fail-closed).
 *
 * @param userId The user.
 * @returns The condition.
 */
export function userEnabledCondition(userId: string): SqlCondition {
  return { sql: "EXISTS (SELECT 1 FROM user_enablement WHERE user_id = ? AND enablement = 'enabled')", params: [userId] };
}

/**
 * The user has fewer passkeys than {@link MAX_PASSKEYS_PER_USER}, so one more may be bound. The admin Worker checks
 * it when issuing an enrollment link; the IdP Worker checks it again in the insert, since the user may add a
 * passkey in between.
 *
 * @param userId The user.
 * @returns The condition.
 */
export function passkeyBelowLimitCondition(userId: string): SqlCondition {
  return { sql: `${passkeyCount()} < ?`, params: [userId, MAX_PASSKEYS_PER_USER] };
}

/**
 * The credential belongs to the user and is not the user's last passkey, so deleting it leaves at least one.
 *
 * @param userId The user.
 * @param credentialId The credential to revoke.
 * @returns The condition.
 */
export function passkeyRevocableCondition(userId: string, credentialId: string): SqlCondition {
  return {
    sql: `EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ?) AND ${passkeyCount()} >= 2`,
    params: [credentialId, userId, userId],
  };
}
