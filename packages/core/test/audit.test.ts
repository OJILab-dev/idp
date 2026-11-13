// The audit-row builder (src/shared/audit.ts), checked against the real audit_log table so that the columns and
// CHECK constraints of docs/design/data-model.md are exercised on the engine.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUDIT_DETAIL_COMPUTED_KEYS,
  InvalidAuditRowError,
  PROBLEM_KINDS,
  auditFailureStatement,
  auditSuccessStatement,
  type AuditActor,
  type Database,
} from "../src/shared/index.js";
import { createD1Database } from "../../d1-adapter/src/index.js";
import { createTestD1, type TestD1 } from "../../../contract/test/d1.js";

const NOW = 1_800_000_000;
const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const GROUP = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const ADMIN: AuditActor = { kind: "admin", name: "alice-admin", keyid: "a".repeat(64) };

let t: TestD1;
let db: Database;

function useDatabase(): void {
  beforeEach(async () => {
    t = await createTestD1();
    db = createD1Database(t.db);
  });

  afterEach(async () => {
    await t.dispose();
  });
}

async function rows(): Promise<readonly Record<string, unknown>[]> {
  const [result] = await db.batch([{ sql: "SELECT * FROM audit_log ORDER BY id", params: [] }]);
  return result?.rows ?? [];
}

describe("auditSuccessStatement", () => {
  useDatabase();

  it("writes an admin row with the admin columns and an IDs-only detail", async () => {
    await db.batch([
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "admin-worker@1",
        operation: "group_member_add",
        target: `group:${GROUP}`,
        detail: { user_id: USER },
      }),
    ]);
    expect(await rows()).toEqual([
      {
        id: 1,
        occurred_at: NOW,
        actor: "admin",
        admin_name: "alice-admin",
        admin_cert_sha256: "a".repeat(64),
        // The keyid of the signing key the admin Worker verified (docs/design/hosting-modes.md 3.9).
        admin_credential: "signing-key",
        writer_version: "admin-worker@1",
        operation: "group_member_add",
        target: `group:${GROUP}`,
        result: "success",
        detail_json: JSON.stringify({ user_id: USER }),
      },
    ]);
  });

  it("writes a user row without the admin columns", async () => {
    await db.batch([
      auditSuccessStatement({
        occurredAt: NOW,
        actor: { kind: "user" },
        writerVersion: "worker@1",
        operation: "passkey_add",
        target: `user:${USER}`,
        detail: { credential_id: "AAEC" },
      }),
    ]);
    const [row] = await rows();
    expect(row).toMatchObject({ actor: "user", admin_name: null, admin_cert_sha256: null, admin_credential: null, result: "success" });
  });

  it("does not name admin_credential in a user row, so the IdP Worker does not depend on migration 0004", () => {
    const statement = auditSuccessStatement({
      occurredAt: NOW,
      actor: { kind: "user" },
      writerVersion: "worker@1",
      operation: "passkey_add",
      target: `user:${USER}`,
      detail: { credential_id: "AAEC" },
    });
    expect(statement.sql).not.toContain("admin_credential");
  });

  it("writes nothing when the guard is false, and one row when it is true", async () => {
    const base = {
      occurredAt: NOW,
      actor: ADMIN,
      writerVersion: "v",
      operation: "user_disable",
      target: `user:${USER}`,
      detail: {},
    } as const;
    await db.batch([
      auditSuccessStatement({ ...base, guard: { sql: "1 = ?", params: [0] } }),
      auditSuccessStatement({ ...base, guard: { sql: "1 = ?", params: [1] } }),
    ]);
    expect(await rows()).toHaveLength(1);
  });

  it("merges computed members into the detail with SQL, as JSON values", async () => {
    await db.batch([
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "grant_add",
        target: "client:grafana",
        detail: { principal: `user:${USER}` },
        computed: [
          { key: "newly_enabled", sql: "SELECT json_array(json_object('user_id', ?, 'client_id', 'grafana'))", params: [USER] },
          { key: "sessions_deleted", sql: "SELECT 3", params: [] },
        ],
      }),
    ]);
    const [row] = await rows();
    expect(JSON.parse(row?.["detail_json"] as string)).toEqual({
      principal: `user:${USER}`,
      newly_enabled: [{ user_id: USER, client_id: "grafana" }],
      sessions_deleted: 3,
    });
  });

  it("only computes the members it knows", () => {
    expect([...AUDIT_DETAIL_COMPUTED_KEYS].sort()).toEqual(["newly_enabled", "sessions_deleted"]);
  });
});

describe("auditFailureStatement", () => {
  useDatabase();

  it("writes an admin failure row with the problem kind", async () => {
    await db.batch([
      auditFailureStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "user_rename",
        target: `user:${USER}`,
        problem: "not-found",
      }),
    ]);
    const [row] = await rows();
    expect(row).toMatchObject({ result: "failure", target: `user:${USER}`, detail_json: '{"problem":"not-found"}' });
  });

  it("knows every problem kind of docs/design/idpctl.md", () => {
    expect([...PROBLEM_KINDS].sort()).toEqual(
      [
        "validation-failed",
        "not-found",
        "already-exists",
        "state-conflict",
        "limit-reached",
        "last-passkey",
        "algorithm-disabled",
        "secret-not-replayable",
        "idempotency-key-reused",
        "forbidden",
        "internal",
      ].sort(),
    );
  });
});

describe("a name never reaches detail_json", () => {
  // A client ID is chosen by the admin, so a lowercase word is a valid one by contract; every other member rejects it.
  const names = ["Alice Example", "家族", "alice@example.com", "Sales Team", "", " "];
  const keys = ["user_id", "group_id", "client_id", "principal", "credential_id", "enablement", "client_type"];

  it.each(["user_id", "group_id", "principal", "enablement", "client_type", "id_token_alg", "problem"])(
    "rejects a lowercase name in %s",
    (key) => {
      expect(() =>
        auditSuccessStatement({
          occurredAt: NOW,
          actor: ADMIN,
          writerVersion: "v",
          operation: "user_rename",
          target: `user:${USER}`,
          detail: { [key]: "alice" },
        }),
      ).toThrow(InvalidAuditRowError);
    },
  );

  it.each(keys.flatMap((key) => names.map((name) => [key, name] as const)))("rejects %s = %j", (key, name) => {
    expect(() =>
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "user_rename",
        target: `user:${USER}`,
        detail: { [key]: name },
      }),
    ).toThrow(InvalidAuditRowError);
  });

  it.each(["name", "reason", "previous_name", "note"])("rejects the unknown member %s", (key) => {
    expect(() =>
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "user_rename",
        target: `user:${USER}`,
        detail: { [key]: USER },
      }),
    ).toThrow(InvalidAuditRowError);
  });

  it.each(["user:Alice", "group:sales", "client:Grafana App", "alice", "user:", "client:"])("rejects the target %j", (target) => {
    expect(() =>
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "user_rename",
        target: target as `user:${string}`,
        detail: {},
      }),
    ).toThrow(InvalidAuditRowError);
  });

  it.each([{ nested: { user_id: USER } }, [USER], 1.5, -1, true])("rejects the value %j where a number or ID is expected", (value) => {
    expect(() =>
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "enroll_link_issue",
        target: `user:${USER}`,
        detail: { expires_at: value } as never,
      }),
    ).toThrow(InvalidAuditRowError);
  });

  it("accepts registered redirect URIs and rejects a name hidden in the list", () => {
    const row = { occurredAt: NOW, actor: ADMIN, writerVersion: "v", operation: "client_set_redirects", target: "client:grafana" } as const;
    expect(() => auditSuccessStatement({ ...row, detail: { redirect_uris: ["https://app.example.com/cb", "http://127.0.0.1/cb"] } })).not.toThrow();
    expect(() => auditSuccessStatement({ ...row, detail: { redirect_uris: ["https://app.example.com/cb", "Alice's laptop"] } })).toThrow(
      InvalidAuditRowError,
    );
    expect(() => auditSuccessStatement({ ...row, detail: { redirect_uris: "https://app.example.com/cb" } })).toThrow(InvalidAuditRowError);
  });

  it("accepts https post-logout redirect URIs only", () => {
    const row = { occurredAt: NOW, actor: ADMIN, writerVersion: "v", operation: "client_set_post_logout_redirects", target: "client:grafana" } as const;
    expect(() => auditSuccessStatement({ ...row, detail: { post_logout_redirect_uris: [] } })).not.toThrow();
    expect(() => auditSuccessStatement({ ...row, detail: { post_logout_redirect_uris: ["https://app.example.com/bye"] } })).not.toThrow();
    expect(() => auditSuccessStatement({ ...row, detail: { post_logout_redirect_uris: ["http://127.0.0.1/bye"] } })).toThrow(InvalidAuditRowError);
    expect(() => auditSuccessStatement({ ...row, detail: { post_logout_redirect_uris: ["Alice's laptop"] } })).toThrow(InvalidAuditRowError);
  });

  it("rejects an operation name that is not snake_case", () => {
    expect(() =>
      auditSuccessStatement({
        occurredAt: NOW,
        actor: ADMIN,
        writerVersion: "v",
        operation: "rename Alice",
        target: "none",
        detail: {},
      }),
    ).toThrow(InvalidAuditRowError);
  });

  it("rejects an admin actor without a name or a SHA-256 keyid", () => {
    const row = { occurredAt: NOW, writerVersion: "v", operation: "user_create", target: "none", detail: {} } as const;
    expect(() => auditSuccessStatement({ ...row, actor: { kind: "admin", name: "", keyid: "a".repeat(64) } })).toThrow(
      InvalidAuditRowError,
    );
    expect(() => auditSuccessStatement({ ...row, actor: { kind: "admin", name: "a", keyid: "xyz" } })).toThrow(
      InvalidAuditRowError,
    );
  });
});
