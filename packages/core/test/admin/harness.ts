// A real local D1 with the migrations applied, wrapped as an AdminContext, so every admin rule is tested against
// the schema's constraints, triggers, and views rather than a mock.
import { afterEach, beforeEach } from "vitest";
import {
  executeOperation,
  type AdminContext,
  type AdminOperation,
  type OperationOutcome,
} from "../../src/admin/index.js";
import { parseIssuer, randomToken, type Database, type SqlRow, type SqlValue } from "../../src/shared/index.js";
import { createD1Database } from "../../../d1-adapter/src/index.js";
import { createTestD1, type TestD1 } from "../../../../contract/test/d1.js";

export const T0 = 1_800_000_000;
export const ROOT = { name: "root", certSha256: "a".repeat(64) } as const;

/** The state of one test: the database, a context whose clock and settings the test can change, and helpers. */
export type Harness = {
  readonly db: Database;
  clock: number;
  rs256Enabled: boolean;
  admin: { readonly name: string; readonly certSha256: string };
  readonly failureAuditErrors: unknown[];
  readonly ctx: () => AdminContext;
};

/**
 * Registers beforeEach/afterEach hooks that give each test a fresh database.
 *
 * @returns A getter for the current test's harness.
 */
export function useHarness(): () => Harness {
  let t: TestD1 | undefined;
  let h: Harness | undefined;
  beforeEach(async () => {
    t = await createTestD1();
    const db = createD1Database(t.db);
    const state: Harness = {
      db,
      clock: T0,
      rs256Enabled: false,
      admin: ROOT,
      failureAuditErrors: [],
      ctx: () => ({
        db: state.db,
        admin: state.admin,
        writerVersion: "admin-worker@test",
        now: () => state.clock,
        rs256Enabled: state.rs256Enabled,
        issuer: parseIssuer("https://idp.example.com"),
        onFailureAuditError: (error) => state.failureAuditErrors.push(error),
      }),
    };
    h = state;
  });
  afterEach(async () => {
    await t?.dispose();
  });
  return () => {
    if (h === undefined) throw new Error("harness used outside a test");
    return h;
  };
}

/**
 * Runs an operation, supplying a fresh Idempotency-Key unless the caller passes one (or null for none).
 */
export function run<I, R>(h: Harness, operation: AdminOperation<I, R>, input: unknown, key?: string | null): Promise<OperationOutcome<R>> {
  const idempotencyKey = key === null ? undefined : (key ?? randomToken());
  return executeOperation(h.ctx(), operation, input, { idempotencyKey });
}

/** Runs one SQL statement and returns its rows. */
export async function query(h: Harness, sql: string, ...params: SqlValue[]): Promise<readonly SqlRow[]> {
  const [result] = await h.db.batch([{ sql, params }]);
  return result?.rows ?? [];
}

/** The audit rows, oldest first, with detail_json parsed. */
export async function auditRows(h: Harness): Promise<readonly Record<string, unknown>[]> {
  const rows = await query(h, "SELECT * FROM audit_log ORDER BY id");
  return rows.map((row) => ({ ...row, detail: JSON.parse(row["detail_json"] as string) as unknown }));
}

/** The effective_access view as sorted `user_id client_id` strings. */
export async function effectiveAccess(h: Harness): Promise<readonly string[]> {
  const rows = await query(h, "SELECT user_id, client_id FROM effective_access ORDER BY user_id, client_id");
  return rows.map((row) => `${String(row["user_id"])} ${String(row["client_id"])}`);
}

let credentialCounter = 0;

/** Inserts a passkey for a user directly, standing in for the IdP Worker's enrollment. */
export async function seedPasskey(h: Harness, userId: string): Promise<string> {
  credentialCounter += 1;
  const id = `cred${String(credentialCounter).padStart(4, "0")}`;
  await query(
    h,
    "INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via) VALUES (?, ?, ?, 0, 1, 0, ?, 'enroll')",
    id,
    userId,
    new Uint8Array([1, 2, 3]),
    h.clock,
  );
  return id;
}

/** Inserts a session for a user on one of their passkeys. */
export async function seedSession(h: Harness, userId: string, credentialId: string): Promise<void> {
  await query(
    h,
    "INSERT INTO sessions (token_hash, user_id, credential_id, auth_time, expires_at) VALUES (?, ?, ?, ?, ?)",
    randomToken(),
    userId,
    credentialId,
    h.clock,
    h.clock + 3600,
  );
}

/** Inserts an enabled client directly (client operations arrive in a later stage of the stack). */
export async function seedClient(h: Harness, clientId: string): Promise<void> {
  await h.db.batch([
    {
      sql:
        "INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, id_token_signed_response_alg, created_at) " +
        "VALUES (?, 'App', 'public', NULL, '[]', 'Ed25519', ?)",
      params: [clientId, h.clock],
    },
    { sql: "INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES (?, 'enabled', ?)", params: [clientId, h.clock] },
  ]);
}

/** Inserts a grant directly. */
export async function seedGrant(h: Harness, principalId: string, clientId: string): Promise<void> {
  await query(h, "INSERT INTO client_access (principal_id, client_id, created_at) VALUES (?, ?, ?)", principalId, clientId, h.clock);
}
