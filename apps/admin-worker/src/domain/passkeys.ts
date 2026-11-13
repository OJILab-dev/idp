// enroll_link_issue and passkey_revoke (docs/design/idpctl.md, docs/design/authentication.md). Both use the shared
// passkey rules, so the admin Worker and the IdP Worker apply the same limit and the same last-passkey rule.
import { enrollLinkIssueOutput, passkeyRevokeOutput } from "./outputs.js";
import { z } from "zod";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isCredentialId, randomToken } from "@idp/core/identifiers";
import {
  passkeyBelowLimitCondition,
  passkeyRevocableCondition,
  userEnabledCondition,
  MAX_PASSKEYS_PER_USER,
} from "@idp/core/passkeys";
import type { WriteOperation } from "./operation.js";
import { AdminProblem } from "./problem.js";
import { uuidSchema } from "./schemas.js";

/**
 * How long an enrollment link stays valid: the 10-minute maximum NIST SP 800-63B-4 sets for a binding code used
 * across endpoints (docs/design/authentication.md).
 */
export const ENROLL_LINK_TTL_SECONDS = 10 * 60;

/** The result of enroll_link_issue; the link carries the token and is returned once. */
export type EnrollLinkIssueResult = {
  readonly user_id: string;
  /** `<issuer>/enroll#<token>`: the token sits in the fragment so it never reaches a server log. */
  readonly enrollment_link: string;
  readonly expires_at: number;
};

/**
 * enroll_link_issue: issues the one live enrollment link of an enabled user below the passkey limit. The same batch
 * deletes the user's unused tokens, so at most one link per user works, and deletes expired tokens of all users.
 * The token is stored only as its hash, and the response is never kept for Idempotency-Key replay.
 */
export const enrollLinkIssue: WriteOperation<{ readonly user_id: string }, EnrollLinkIssueResult> = {
  name: "enroll_link_issue",
  class: { access: "write", concern: "user" },
  establishesIdentity: true,
  idempotent: true,
  target: { kind: "user", field: "user_id" },
  input: z.strictObject({ user_id: uuidSchema }),
  http: { method: "POST", path: "/v1/users/{id}/enrollment-links", status: 201 },
  output: enrollLinkIssueOutput,
  async plan(ctx, input) {
    const now = ctx.now();
    const userId = input.user_id;
    const token = randomToken();
    const tokenHash = await sha256Base64url(token);
    const expiresAt = now + ENROLL_LINK_TTL_SECONDS;
    const enabled = userEnabledCondition(userId);
    const belowLimit = passkeyBelowLimitCondition(userId);
    const guard = { sql: `${enabled.sql} AND ${belowLimit.sql}`, params: [...enabled.params, ...belowLimit.params] };
    return {
      target: `user:${userId}`,
      probe: {
        sql:
          "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?) AS found, " +
          `${enabled.sql} AS enabled, (SELECT COUNT(*) FROM credentials WHERE user_id = ?) AS passkeys`,
        params: [userId, ...enabled.params, userId],
      },
      guard,
      writes: [
        { sql: `DELETE FROM enroll_tokens WHERE (user_id = ? OR expires_at <= ?) AND ${guard.sql}`, params: [userId, now, ...guard.params] },
        {
          sql: `INSERT INTO enroll_tokens (token_hash, user_id, expires_at) SELECT ?, ?, ? WHERE ${guard.sql}`,
          params: [tokenHash, userId, expiresAt, ...guard.params],
        },
      ],
      detail: { expires_at: expiresAt },
      secret: true,
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The user does not exist");
        if (probe["enabled"] !== 1) throw new AdminProblem("state-conflict", "The user is disabled");
        if ((probe["passkeys"] as number) >= MAX_PASSKEYS_PER_USER) {
          throw new AdminProblem("limit-reached", "The user already has the maximum number of passkeys; revoke one first");
        }
        return "write";
      },
      result: () => ({ user_id: userId, enrollment_link: `${ctx.issuer.url}/enroll#${token}`, expires_at: expiresAt }),
    };
  },
};

const credentialIdSchema = z.string().refine(isCredentialId, { message: "must be a credential ID" });

type PasskeyInput = { readonly user_id: string; readonly credential_id: string };

/**
 * passkey_revoke: deletes one passkey of a user, and through the foreign keys only the sessions signed in with it.
 * The last passkey cannot be revoked; the count is checked in the DELETE itself. A passkey that is not the user's is
 * not-found. Disabling the user is the way to lock them out completely.
 */
export const passkeyRevoke: WriteOperation<PasskeyInput, PasskeyInput> = {
  name: "passkey_revoke",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "user", field: "user_id" },
  input: z.strictObject({ user_id: uuidSchema, credential_id: credentialIdSchema }),
  http: { method: "DELETE", path: "/v1/users/{id}/passkeys/{credential_id}", status: 200 },
  output: passkeyRevokeOutput,
  async plan(_ctx, input) {
    const { user_id: userId, credential_id: credentialId } = input;
    const guard = passkeyRevocableCondition(userId, credentialId);
    return {
      target: `user:${userId}`,
      probe: {
        sql:
          "SELECT EXISTS (SELECT 1 FROM credentials WHERE id = ? AND user_id = ?) AS owned, " +
          "(SELECT COUNT(*) FROM credentials WHERE user_id = ?) AS passkeys",
        params: [credentialId, userId, userId],
      },
      guard,
      writes: [{ sql: `DELETE FROM credentials WHERE id = ? AND user_id = ? AND ${guard.sql}`, params: [credentialId, userId, ...guard.params] }],
      detail: { credential_id: credentialId },
      settle(probe) {
        if (probe["owned"] !== 1) throw new AdminProblem("not-found", "The user has no such passkey");
        if ((probe["passkeys"] as number) < 2) throw new AdminProblem("last-passkey", "The last passkey cannot be revoked; disable the user instead");
        return "write";
      },
      result: () => ({ user_id: userId, credential_id: credentialId }),
    };
  },
};
