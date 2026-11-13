// The OIDC fixture plus what the passkey ceremonies need: users whose stored passkeys are software credentials, the
// RP of the fixture issuer, and a database wrapper that runs a step just before a chosen batch, so a test can make
// the state change between a ceremony's read and its write.
import { base64urlEncode } from "@idp/base64url";
import type { Database, SqlStatement, SqlStatementResult } from "@idp/core/db";
import type { PasskeyDeps } from "../../src/domain/index.js";
import { createFixture, issuer, type Fixture } from "./oidc-fixture.js";
import { generateCredential, type SoftCredential, type TestAlgorithm } from "../../../../packages/webauthn/test/support/webauthn-authenticator.js";

export const rp = { rpId: issuer.rpId, origin: issuer.origin };

export const WRITER_VERSION = "idp-test-1";

/** The OIDC fixture with passkey helpers. */
export type PasskeyFixture = Fixture & {
  readonly passkeyDeps: PasskeyDeps;
  /** Generates a software credential for the user (with their stored user handle) and stores it. */
  readonly addPasskey: (userId: string, options?: { readonly alg?: TestAlgorithm; readonly via?: "enroll" | "self"; readonly signCount?: number }) => Promise<SoftCredential>;
  /** Runs `step` once, right before the batch whose first statement matches `pattern`. */
  readonly beforeBatch: (pattern: RegExp, step: () => Promise<void>) => void;
  readonly count: (table: string, where?: string, ...params: readonly (string | number)[]) => Promise<number>;
};

/**
 * Creates the fixture.
 *
 * @returns The fixture; dispose it after the test.
 */
export async function createPasskeyFixture(): Promise<PasskeyFixture> {
  const base = await createFixture();
  const hooks: { pattern: RegExp; step: () => Promise<void> }[] = [];
  const raw = base.db;
  const db: Database = {
    async batch(statements: readonly SqlStatement[]): Promise<readonly SqlStatementResult[]> {
      const index = hooks.findIndex((h) => statements.some((s) => h.pattern.test(s.sql)));
      const hook = index >= 0 ? hooks.splice(index, 1)[0] : undefined;
      if (hook !== undefined) await hook.step();
      return raw.batch(statements);
    },
  };
  const passkeyDeps: PasskeyDeps = { db, issuer, clock: base.clock, random: base.random, writerVersion: WRITER_VERSION };
  let created = 0;
  return {
    ...base,
    passkeyDeps,
    async addPasskey(userId, options = {}) {
      const [row] = await base.query("SELECT user_handle FROM users WHERE id = ?", userId);
      const credential = await generateCredential(options.alg ?? -8, {
        userHandle: row?.["user_handle"] as Uint8Array,
        signCount: options.signCount ?? 0,
      });
      created += 1;
      await base.run(
        `INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via)
         VALUES (?, ?, ?, ?, 1, 1, ?, ?)`,
        base64urlEncode(credential.id),
        userId,
        credential.cosePublicKey,
        credential.signCount,
        base.clock.now() - 4000 + created,
        options.via ?? "enroll",
      );
      return credential;
    },
    beforeBatch(pattern, step) {
      hooks.push({ pattern, step });
    },
    async count(table, where = "1", ...params) {
      const [row] = await base.query(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`, ...params);
      return row?.["n"] as number;
    },
  };
}

/** The credential's ID as stored. */
export function idOf(credential: SoftCredential): string {
  return base64urlEncode(credential.id);
}
