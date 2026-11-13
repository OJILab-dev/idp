// Conformance of the D1 adapter to the Database port (packages/core/src/shared/db.ts), run against a real local D1
// (workerd's SQLite) with migration 0001 applied, so the properties the core relies on are checked on the engine
// itself rather than on a mock.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DatabaseError, type Database, type SqlStatement } from "@idp/core/shared";
import { createTestD1, type TestD1 } from "../../../../contract/test/d1.js";
import { createD1Database } from "../../src/d1/index.js";

const NOW = 1_800_000_000;

let t: TestD1;
let db: Database;

beforeEach(async () => {
  t = await createTestD1();
  db = createD1Database(t.db);
});

afterEach(async () => {
  await t.dispose();
});

function stmt(sql: string, ...params: SqlStatement["params"]): SqlStatement {
  return { sql, params };
}

function insertUser(id: string, handle: Uint8Array): readonly SqlStatement[] {
  return [
    stmt("INSERT INTO principals (id, kind) VALUES (?, 'user')", id),
    stmt("INSERT INTO users (id, user_handle, name, created_at) VALUES (?, ?, 'n', ?)", id, handle, NOW),
  ];
}

async function count(table: string): Promise<number> {
  const [result] = await db.batch([stmt(`SELECT COUNT(*) AS n FROM ${table}`)]);
  return result?.rows[0]?.["n"] as number;
}

describe("createD1Database", () => {
  it("resolves an empty batch to [] without calling the binding", async () => {
    const binding = {
      prepare: () => {
        throw new Error("prepare must not be called");
      },
      batch: () => {
        throw new Error("batch must not be called");
      },
    } as unknown as D1Database;
    await expect(createD1Database(binding).batch([])).resolves.toEqual([]);
  });

  it("returns one result per statement, in statement order", async () => {
    const results = await db.batch([
      stmt("SELECT 1 AS v"),
      stmt("SELECT 'a' AS v UNION ALL SELECT 'b'"),
      stmt("SELECT 3 AS v WHERE 0"),
    ]);
    expect(results).toEqual([
      { rows: [{ v: 1 }], changes: 0 },
      { rows: [{ v: "a" }, { v: "b" }], changes: 0 },
      { rows: [], changes: 0 },
    ]);
  });

  it("reports changes for INSERT, UPDATE, DELETE, and SELECT", async () => {
    await db.batch(insertUser("u1", new Uint8Array(64)));
    const results = await db.batch([
      stmt(
        "INSERT INTO enroll_tokens (token_hash, user_id, expires_at) VALUES ('a', 'u1', ?), ('b', 'u1', ?), ('c', 'u1', ?)",
        NOW,
        NOW,
        NOW,
      ),
      stmt("UPDATE enroll_tokens SET expires_at = ? WHERE token_hash IN ('a', 'b')", NOW + 1),
      stmt("DELETE FROM enroll_tokens WHERE token_hash = 'c'"),
      stmt("SELECT token_hash FROM enroll_tokens ORDER BY token_hash"),
    ]);
    expect(results.map((r) => r.changes)).toEqual([3, 2, 1, 0]);
    expect(results[3]?.rows).toEqual([{ token_hash: "a" }, { token_hash: "b" }]);
  });

  it("consumes a row exactly once with DELETE … RETURNING", async () => {
    await db.batch([
      ...insertUser("u1", new Uint8Array(64)),
      stmt("INSERT INTO enroll_tokens (token_hash, user_id, expires_at) VALUES ('h', 'u1', ?)", NOW + 600),
    ]);
    const consume = stmt("DELETE FROM enroll_tokens WHERE token_hash = 'h' AND expires_at > ? RETURNING user_id", NOW);
    expect(await db.batch([consume])).toEqual([{ rows: [{ user_id: "u1" }], changes: 1 }]);
    expect(await db.batch([consume])).toEqual([{ rows: [], changes: 0 }]);
  });

  it("round-trips BLOBs as equal bytes", async () => {
    const handle = crypto.getRandomValues(new Uint8Array(64));
    // Every byte value, so no encoding (UTF-8, base64, signed bytes) can pass by accident.
    const publicKey = Uint8Array.from({ length: 256 }, (_, i) => i);
    await db.batch([
      ...insertUser("u1", handle),
      stmt(
        `INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via)
         VALUES ('cred', 'u1', ?, 0, 0, 0, ?, 'enroll')`,
        publicKey,
        NOW,
      ),
    ]);
    const [users, credentials, empty] = await db.batch([
      stmt("SELECT user_handle FROM users WHERE id = 'u1'"),
      stmt("SELECT public_key FROM credentials WHERE id = 'cred'"),
      stmt("SELECT x'' AS b"),
    ]);
    expect(users?.rows[0]?.["user_handle"]).toEqual(handle);
    expect(credentials?.rows[0]?.["public_key"]).toEqual(publicKey);
    expect(empty?.rows[0]?.["b"]).toEqual(new Uint8Array(0));
    // A BLOB binds as bytes, so it matches a BLOB literal and not its text form.
    const [match] = await db.batch([stmt("SELECT id FROM credentials WHERE public_key = ?", publicKey)]);
    expect(match?.rows).toEqual([{ id: "cred" }]);
  });

  it("rolls back the first statement when the second fails, and throws a DatabaseError with the cause", async () => {
    const error = await db
      .batch([
        stmt("INSERT INTO principals (id, kind) VALUES ('u1', 'user')"),
        stmt("INSERT INTO principals (id, kind) VALUES ('u1', 'user')"),
      ])
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DatabaseError);
    expect((error as DatabaseError).cause).toBeInstanceOf(Error);
    expect(String((error as DatabaseError).cause)).toMatch(/UNIQUE/);
    expect(await count("principals")).toBe(0);
  });

  it("rolls back the whole batch when a trigger RAISE(ABORT) fires, as a DatabaseError", async () => {
    await db.batch([
      stmt(
        `INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, id_token_signed_response_alg, created_at)
         VALUES ('c1', 'c', 'public', NULL, '[]', 'Ed25519', ?)`,
        NOW,
      ),
      stmt("INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES ('c1', 'enabled', ?)", NOW),
    ]);
    const error = await db
      .batch([
        stmt("INSERT INTO client_enablement_events (client_id, enablement, occurred_at) VALUES ('c1', 'disabled', ?)", NOW),
        stmt("DELETE FROM clients WHERE id = 'c1'"),
      ])
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DatabaseError);
    expect(String((error as DatabaseError).cause)).toMatch(/never deleted/);
    const [state] = await db.batch([stmt("SELECT enablement FROM client_enablement WHERE client_id = 'c1'")]);
    expect(state?.rows).toEqual([{ enablement: "enabled" }]);
    expect(await count("client_enablement_events")).toBe(1);
  });

  it("turns an error thrown synchronously by the binding into a DatabaseError", async () => {
    const cause = new Error("binding broke");
    const binding = {
      prepare: () => {
        throw cause;
      },
    } as unknown as D1Database;
    const error = await createD1Database(binding)
      .batch([stmt("SELECT 1")])
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DatabaseError);
    expect((error as DatabaseError).cause).toBe(cause);
  });

  it("normalises every form D1 may return a BLOB in to a Uint8Array", async () => {
    const bytes = [0, 1, 254, 255];
    const binding = {
      prepare: () => ({ bind: () => ({}) }),
      batch: () =>
        Promise.resolve([
          {
            results: [{ buffer: Uint8Array.from(bytes).buffer, array: bytes, view: Uint8Array.from([9, ...bytes]).subarray(1) }],
            meta: { changes: 0 },
            success: true,
          },
        ]),
    } as unknown as D1Database;
    const [result] = await createD1Database(binding).batch([stmt("SELECT 1")]);
    const expected = Uint8Array.from(bytes);
    expect(result?.rows).toEqual([{ buffer: expected, array: expected, view: expected }]);
  });

  it("rejects a binding result whose length differs from the statements, instead of returning partial results", async () => {
    const binding = {
      prepare: () => ({ bind: () => ({}) }),
      batch: () => Promise.resolve([{ results: [], meta: { changes: 0 }, success: true }]),
    } as unknown as D1Database;
    await expect(createD1Database(binding).batch([stmt("SELECT 1"), stmt("SELECT 2")])).rejects.toBeInstanceOf(
      DatabaseError,
    );
  });
});
