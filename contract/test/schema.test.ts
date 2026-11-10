import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { D1Database } from "@cloudflare/workers-types";
import { createTestD1, migrationNames, readMigration, splitStatements, type TestD1 } from "./d1.js";

const NOW = 1_800_000_000;

let t: TestD1;
let db: D1Database;

beforeEach(async () => {
  t = await createTestD1();
  db = t.db;
});

afterEach(async () => {
  await t.dispose();
});

async function addUser(id: string, enablement: "enabled" | "disabled" | null = "enabled"): Promise<void> {
  await db.batch([
    db.prepare("INSERT INTO principals (id, kind) VALUES (?, 'user')").bind(id),
    db.prepare("INSERT INTO users (id, user_handle, name, created_at) VALUES (?, randomblob(64), 'n', ?)").bind(id, NOW),
  ]);
  if (enablement !== null) {
    await db
      .prepare("INSERT INTO user_enablement_events (user_id, enablement, occurred_at) VALUES (?, ?, ?)")
      .bind(id, enablement, NOW)
      .run();
  }
}

async function addGroup(id: string, enablement: "enabled" | "disabled" = "enabled"): Promise<void> {
  await db.batch([
    db.prepare("INSERT INTO principals (id, kind) VALUES (?, 'group')").bind(id),
    db.prepare("INSERT INTO groups (id, name, created_at) VALUES (?, ?, ?)").bind(id, `g-${id}`, NOW),
    db
      .prepare("INSERT INTO group_enablement_events (group_id, enablement, occurred_at) VALUES (?, ?, ?)")
      .bind(id, enablement, NOW),
  ]);
}

async function addClient(id: string, enablement: "enabled" | "disabled" = "enabled"): Promise<void> {
  await db.batch([
    db
      .prepare(
        `INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, id_token_signed_response_alg, created_at)
         VALUES (?, 'c', 'public', NULL, '[]', 'Ed25519', ?)`,
      )
      .bind(id, NOW),
    db
      .prepare("INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES (?, ?, ?)")
      .bind(id, enablement, NOW),
  ]);
}

async function grant(principalId: string, clientId: string): Promise<void> {
  await db
    .prepare("INSERT INTO client_access (principal_id, client_id, created_at) VALUES (?, ?, ?)")
    .bind(principalId, clientId, NOW)
    .run();
}

async function effectiveAccess(): Promise<readonly string[]> {
  const { results } = await db
    .prepare("SELECT user_id || '>' || client_id AS pair FROM effective_access ORDER BY pair")
    .all<{ pair: string }>();
  return results.map((r) => r.pair);
}

describe("the migrations", () => {
  it("are numbered 0001, 0002, … without gaps", () => {
    const names = migrationNames();
    expect(names[0]).toBe("0001_init.sql");
    names.forEach((name, i) => expect(name.slice(0, 4)).toBe(String(i + 1).padStart(4, "0")));
  });

  it("are exactly the SQL blocks of docs/design/data-model.md, one block per migration in order", () => {
    const doc = readFileSync(join(import.meta.dirname, "..", "..", "docs", "design", "data-model.md"), "utf8");
    const blocks = [...doc.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]);
    expect(blocks.map((_, i) => migrationNames()[i])).toEqual(migrationNames());
    migrationNames().forEach((name, i) => expect(readMigration(name)).toBe(blocks[i]));
  });

  it.each(migrationNames())("%s has no string literal that the statement splitter could cut", (name) => {
    for (const literal of readMigration(name).match(/'[^']*'/g) ?? []) {
      expect(literal).not.toMatch(/;|--/);
    }
    expect(splitStatements(readMigration(name)).length).toBeGreaterThan(0);
  });

  it("creates the 16 tables, audit_log, admin_request_nonces, and the four views", async () => {
    const { results } = await db
      .prepare("SELECT type, name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite%'")
      .all<{ type: string; name: string }>();
    const tables = results.filter((r) => r.type === "table").map((r) => r.name);
    const views = results.filter((r) => r.type === "view").map((r) => r.name).sort();
    expect(tables.filter((n) => n !== "audit_log" && n !== "admin_request_nonces")).toHaveLength(16);
    expect(tables).toContain("audit_log");
    expect(tables).toContain("admin_request_nonces");
    expect(views).toEqual(["client_enablement", "effective_access", "group_enablement", "user_enablement"]);
  });
});

describe("append-only and never-deleted rows (triggers)", () => {
  it.each(["user", "client", "group"] as const)("rejects UPDATE and DELETE on %s_enablement_events", async (kind) => {
    if (kind === "user") await addUser("u1");
    if (kind === "client") await addClient("c1");
    if (kind === "group") await addGroup("g1");
    const table = `${kind}_enablement_events`;
    await expect(db.prepare(`UPDATE ${table} SET enablement = 'disabled'`).run()).rejects.toThrow(/append-only/);
    await expect(db.prepare(`DELETE FROM ${table}`).run()).rejects.toThrow(/append-only/);
  });

  it("rejects DELETE on principals, users, clients, and groups", async () => {
    await addUser("u1", null);
    await addGroup("g1");
    await addClient("c1");
    await expect(db.prepare("DELETE FROM users").run()).rejects.toThrow(/never deleted/);
    await expect(db.prepare("DELETE FROM principals WHERE id = 'u1'").run()).rejects.toThrow(/never deleted/);
    await expect(db.prepare("DELETE FROM clients").run()).rejects.toThrow(/never deleted/);
    await expect(db.prepare("DELETE FROM groups").run()).rejects.toThrow(/never deleted/);
  });

  describe("audit_log", () => {
    async function addAuditRow(): Promise<void> {
      await db
        .prepare(
          `INSERT INTO audit_log (occurred_at, actor, admin_name, admin_cert_sha256, writer_version, operation, target, result, detail_json)
           VALUES (?, 'admin', 'root', ?, 'admin-worker@test', 'user_create', 'none', 'success', '{}')`,
        )
        .bind(NOW, "a".repeat(64))
        .run();
    }

    it("accepts INSERT", async () => {
      await addAuditRow();
      await addAuditRow();
      expect(await db.prepare("SELECT COUNT(*) AS n FROM audit_log").first("n")).toBe(2);
    });

    it("rejects UPDATE of any column and leaves the row as written", async () => {
      await addAuditRow();
      await expect(db.prepare("UPDATE audit_log SET result = 'failure'").run()).rejects.toThrow(/audit_log is append-only/);
      await expect(db.prepare("UPDATE audit_log SET detail_json = '{}' WHERE id = 1").run()).rejects.toThrow(/audit_log is append-only/);
      expect(await db.prepare("SELECT result FROM audit_log WHERE id = 1").first("result")).toBe("success");
    });

    it("rejects DELETE", async () => {
      await addAuditRow();
      await expect(db.prepare("DELETE FROM audit_log").run()).rejects.toThrow(/audit_log is append-only/);
      await expect(db.prepare("DELETE FROM audit_log WHERE id = 1").run()).rejects.toThrow(/audit_log is append-only/);
      expect(await db.prepare("SELECT COUNT(*) AS n FROM audit_log").first("n")).toBe(1);
    });

    // REPLACE removes the conflicting row without firing DELETE triggers (recursive_triggers is off), so the row
    // would be rewritten in place; an INSERT that names an existing id is refused instead.
    it.each(["INSERT OR REPLACE", "REPLACE"])("rejects %s over an existing row", async (verb) => {
      await addAuditRow();
      await expect(
        db
          .prepare(
            `${verb} INTO audit_log (id, occurred_at, actor, writer_version, operation, target, result)
             VALUES (1, ?, 'user', 'worker@test', 'passkey_add', 'none', 'success')`,
          )
          .bind(NOW)
          .run(),
      ).rejects.toThrow(/audit_log is append-only/);
      expect(await db.prepare("SELECT actor, operation FROM audit_log WHERE id = 1").first()).toEqual({ actor: "admin", operation: "user_create" });
    });

    it("rolls back the whole batch when a later statement tries to delete audit rows", async () => {
      await addAuditRow();
      await expect(
        db.batch([db.prepare("INSERT INTO principals (id, kind) VALUES ('u1', 'user')"), db.prepare("DELETE FROM audit_log")]),
      ).rejects.toThrow(/audit_log is append-only/);
      expect(await db.prepare("SELECT COUNT(*) AS n FROM principals").first("n")).toBe(0);
    });
  });

  it("rolls back the whole batch when a trigger aborts a later statement", async () => {
    await addClient("c1");
    await expect(
      db.batch([
        db.prepare("INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES ('c1', 'disabled', ?)").bind(NOW),
        db.prepare("DELETE FROM clients WHERE id = 'c1'"),
      ]),
    ).rejects.toThrow(/never deleted/);
    const row = await db.prepare("SELECT enablement FROM client_enablement WHERE client_id = 'c1'").first<{ enablement: string }>();
    expect(row?.enablement).toBe("enabled");
  });
});

describe("batches and single-use values", () => {
  it("rolls back the whole batch when a constraint fails in the second statement", async () => {
    await expect(
      db.batch([
        db.prepare("INSERT INTO principals (id, kind) VALUES ('u1', 'user')"),
        db.prepare("INSERT INTO principals (id, kind) VALUES ('u1', 'user')"),
      ]),
    ).rejects.toThrow();
    expect(await db.prepare("SELECT COUNT(*) AS n FROM principals").first("n")).toBe(0);
  });

  it("consumes a row exactly once with DELETE … RETURNING", async () => {
    await addUser("u1");
    await db.prepare("INSERT INTO enroll_tokens (token_hash, user_id, expires_at) VALUES ('h', 'u1', ?)").bind(NOW + 600).run();
    const consume = db.prepare("DELETE FROM enroll_tokens WHERE token_hash = 'h' AND expires_at > ? RETURNING user_id").bind(NOW);
    expect((await consume.all()).results).toEqual([{ user_id: "u1" }]);
    expect((await consume.all()).results).toEqual([]);
  });
});

// docs/design/hosting-modes.md 3.6: the nonce table of the RFC 9421 admin signatures.
describe("admin_request_nonces (0003)", () => {
  const NONCE = "xMqC-D22YekRFeQyPW_wJURp5-AaaeKbKCOYg7rClew";

  function insertNonce(nonce: string, expiresAt: number | null): Promise<unknown> {
    return db.prepare("INSERT INTO admin_request_nonces (nonce, expires_at) VALUES (?, ?)").bind(nonce, expiresAt).run();
  }

  it("only adds the nonce table and its index, so no current write is affected", () => {
    const statements = splitStatements(readMigration("0003_admin_request_nonces.sql"));
    expect(statements).toHaveLength(2);
    expect(statements[0]).toMatch(/^CREATE TABLE admin_request_nonces \(/);
    expect(statements[1]).toMatch(/^CREATE INDEX admin_request_nonces_expires_at ON admin_request_nonces \(expires_at\);$/);
  });

  it("has exactly the nonce and expires_at columns, no foreign keys, and no triggers", async () => {
    const { results: columns } = await db.prepare("PRAGMA table_info(admin_request_nonces)").all<{ name: string; pk: number; notnull: number }>();
    expect(columns.map((c) => [c.name, c.pk, c.notnull])).toEqual([
      ["nonce", 1, 0],
      ["expires_at", 0, 1],
    ]);
    expect((await db.prepare("PRAGMA foreign_key_list(admin_request_nonces)").all()).results).toEqual([]);
    const triggers = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'admin_request_nonces'").all();
    expect(triggers.results).toEqual([]);
  });

  it("rejects the second insert of the same nonce with the unique constraint (the replay)", async () => {
    await insertNonce(NONCE, NOW + 60);
    await expect(insertNonce(NONCE, NOW + 61)).rejects.toThrow(/UNIQUE/);
    expect(await db.prepare("SELECT COUNT(*) AS n FROM admin_request_nonces").first("n")).toBe(1);
  });

  it("requires expires_at", async () => {
    await expect(insertNonce(NONCE, null)).rejects.toThrow(/NOT NULL/);
  });

  it("deletes the expired rows through the expires_at index", async () => {
    await insertNonce("a", NOW - 1);
    await insertNonce("b", NOW);
    const sweep = "DELETE FROM admin_request_nonces WHERE expires_at < ?";
    const { results: plan } = await db.prepare(`EXPLAIN QUERY PLAN ${sweep}`).bind(NOW).all<{ detail: string }>();
    expect(plan.map((p) => p.detail).join("\n")).toContain("admin_request_nonces_expires_at");
    await db.prepare(sweep).bind(NOW).run();
    expect((await db.prepare("SELECT nonce FROM admin_request_nonces").all()).results).toEqual([{ nonce: "b" }]);
  });
});

describe("identity constraints", () => {
  it("prevents one id from being both a user and a group", async () => {
    await addGroup("x");
    await expect(
      db.prepare("INSERT INTO users (id, user_handle, name, created_at) VALUES ('x', randomblob(64), 'n', ?)").bind(NOW).run(),
    ).rejects.toThrow(/FOREIGN KEY/);
  });

  it("requires a secret hash exactly for confidential clients", async () => {
    function insert(type: string, secret: string | null) {
      return db
        .prepare(
          `INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, id_token_signed_response_alg, created_at)
           VALUES (?, 'c', ?, ?, '[]', 'Ed25519', ?)`,
        )
        .bind(`c-${type}-${secret ?? "none"}`, type, secret, NOW)
        .run();
    }
    await expect(insert("confidential", null)).rejects.toThrow(/CHECK/);
    await expect(insert("public", "h")).rejects.toThrow(/CHECK/);
    await expect(insert("confidential", "h")).resolves.toBeDefined();
  });

  it("ties each challenge purpose to exactly its binding columns", async () => {
    await addUser("u1");
    function signIn(userId: string | null) {
      return db
        .prepare("INSERT INTO challenges (challenge, purpose, user_id, expires_at) VALUES (?, 'sign_in', ?, ?)")
        .bind(crypto.randomUUID(), userId, NOW)
        .run();
    }
    // sign_in needs an authorize request and must not carry a user
    await expect(signIn(null)).rejects.toThrow(/CHECK/);
    await expect(signIn("u1")).rejects.toThrow(/CHECK/);
  });
});

describe("effective_access", () => {
  beforeEach(async () => {
    await addClient("app");
    await addUser("alice");
    await addUser("bob");
    await addGroup("family");
    await db.prepare("INSERT INTO group_members (user_id, group_id) VALUES ('bob', 'family')").run();
    await grant("alice", "app");
    await grant("family", "app");
  });

  it("grants directly and through an enabled group", async () => {
    expect(await effectiveAccess()).toEqual(["alice>app", "bob>app"]);
  });

  it("excludes a disabled user, a disabled group, and a disabled client", async () => {
    await db.prepare("INSERT INTO user_enablement_events (user_id, enablement, occurred_at) VALUES ('alice', 'disabled', ?)").bind(NOW).run();
    expect(await effectiveAccess()).toEqual(["bob>app"]);
    await db.prepare("INSERT INTO group_enablement_events (group_id, enablement, occurred_at) VALUES ('family', 'disabled', ?)").bind(NOW).run();
    expect(await effectiveAccess()).toEqual([]);
    await db.prepare("INSERT INTO user_enablement_events (user_id, enablement, occurred_at) VALUES ('alice', 'enabled', ?)").bind(NOW).run();
    await db.prepare("INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES ('app', 'disabled', ?)").bind(NOW).run();
    expect(await effectiveAccess()).toEqual([]);
  });

  it("treats a user with no enablement event as disabled (fail-closed)", async () => {
    await addUser("carol", null);
    await grant("carol", "app");
    expect(await effectiveAccess()).not.toContain("carol>app");
  });

  it("uses the latest event as the current state", async () => {
    for (const e of ["disabled", "enabled", "disabled"]) {
      await db.prepare("INSERT INTO user_enablement_events (user_id, enablement, occurred_at) VALUES ('alice', ?, ?)").bind(e, NOW).run();
    }
    expect(await effectiveAccess()).toEqual(["bob>app"]);
  });
});

describe("audit_log constraints", () => {
  function insert(actor: string, adminName: string | null, cert: string | null, result: string) {
    return db
      .prepare(
        `INSERT INTO audit_log (occurred_at, actor, admin_name, admin_cert_sha256, writer_version, operation, target, result)
         VALUES (?, ?, ?, ?, 'v', 'op', 'none', ?)`,
      )
      .bind(NOW, actor, adminName, cert, result)
      .run();
  }

  it("requires the admin name and certificate exactly on admin rows", async () => {
    await expect(insert("admin", "a", "f", "failure")).resolves.toBeDefined();
    await expect(insert("admin", null, "f", "success")).rejects.toThrow(/CHECK/);
    await expect(insert("user", "a", "f", "success")).rejects.toThrow(/CHECK/);
    await expect(insert("break_glass", "a", null, "success")).rejects.toThrow(/CHECK/);
    await expect(insert("break_glass", null, null, "success")).resolves.toBeDefined();
  });

  it("allows failure rows only for admin", async () => {
    await expect(insert("user", null, null, "failure")).rejects.toThrow(/CHECK/);
    await expect(insert("break_glass", null, null, "failure")).rejects.toThrow(/CHECK/);
  });

  it("rejects unknown actors", async () => {
    await expect(insert("operator", null, null, "success")).rejects.toThrow(/CHECK/);
  });
});
