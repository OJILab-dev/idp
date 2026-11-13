import { describe, expect, it } from "vitest";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { IDEMPOTENCY_TTL_SECONDS, executeOperation, requestHash } from "../../src/domain/index.js";
import { groupCreate } from "../../src/domain/groups.js";
import { userCreate, userDisable } from "../../src/domain/users.js";
import { randomToken } from "@idp/core/identifiers";
import type { Database } from "@idp/core/db";
import { T0, auditRows, query, run, useHarness } from "./harness.js";

const h = useHarness();

async function keyRows(): Promise<readonly Record<string, unknown>[]> {
  return query(h(), "SELECT admin_name, operation, replayable, response_status, response_json, expires_at FROM idempotency_keys ORDER BY rowid");
}

describe("Idempotency-Key", () => {
  it("is required by idempotent operations: absent or malformed is validation-failed with a failure row", async () => {
    await expect(run(h(), userCreate, { name: "A" }, null)).rejects.toMatchObject({ kind: "validation-failed" });
    await expect(run(h(), userCreate, { name: "A" }, "short")).rejects.toMatchObject({ kind: "validation-failed" });
    await expect(run(h(), userCreate, { name: "A" }, `${randomToken().slice(0, 42)}+`)).rejects.toMatchObject({ kind: "validation-failed" });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 0 }]);
    expect((await auditRows(h())).map((r) => r["result"])).toEqual(["failure", "failure", "failure"]);
  });

  it("stores the response in the operation's batch for 24 hours, in the admin's namespace", async () => {
    const outcome = await run(h(), userCreate, { name: "A" });
    expect(await keyRows()).toEqual([
      {
        admin_name: "root",
        operation: "user_create",
        replayable: 1,
        response_status: 201,
        response_json: JSON.stringify(outcome.body),
        expires_at: T0 + IDEMPOTENCY_TTL_SECONDS,
      },
    ]);
  });

  it("replays the stored response for the same key and input, without a second write or audit row", async () => {
    const key = randomToken();
    const first = await run(h(), userCreate, { name: "A" }, key);
    const second = await run(h(), userCreate, { name: "A" }, key);
    expect(second).toEqual({ status: 201, body: first.body, replayed: true });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 1 }]);
    expect(await auditRows(h())).toHaveLength(1);
  });

  it("is idempotency-key-reused for the same key with another input or another operation", async () => {
    const key = randomToken();
    await run(h(), userCreate, { name: "A" }, key);
    await expect(run(h(), userCreate, { name: "B" }, key)).rejects.toMatchObject({ kind: "idempotency-key-reused" });
    await expect(run(h(), groupCreate, { name: "A" }, key)).rejects.toMatchObject({ kind: "idempotency-key-reused" });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM principals")).toEqual([{ n: 1 }]);
    expect((await auditRows(h())).slice(1).map((r) => r["detail"])).toEqual([
      { problem: "idempotency-key-reused" },
      { problem: "idempotency-key-reused" },
    ]);
  });

  it("hashes path IDs too, so one key cannot replay one user's enablement for another", async () => {
    const a = (await run(h(), userCreate, { name: "A" })).body.user_id;
    const b = (await run(h(), userCreate, { name: "B" })).body.user_id;
    const key = randomToken();
    await run(h(), userDisable, { user_id: a }, key);
    await expect(run(h(), userDisable, { user_id: b }, key)).rejects.toMatchObject({ kind: "idempotency-key-reused" });
  });

  it("keeps keys of different admins apart", async () => {
    const key = randomToken();
    await run(h(), userCreate, { name: "A" }, key);
    h().admin = { name: "other", keyid: "b".repeat(64) };
    const other = await run(h(), userCreate, { name: "A" }, key);
    expect(other.replayed).toBe(false);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 2 }]);
  });

  it("forgets a key after 24 hours and deletes expired keys in the next batch that writes one", async () => {
    const key = randomToken();
    await run(h(), userCreate, { name: "A" }, key);
    h().clock = T0 + IDEMPOTENCY_TTL_SECONDS;
    const again = await run(h(), userCreate, { name: "A" }, key);
    expect(again.replayed).toBe(false);
    expect(await keyRows()).toEqual([expect.objectContaining({ expires_at: T0 + 2 * IDEMPOTENCY_TTL_SECONDS })]);
  });

  it("stores no key when the operation is rejected, so a fixed retry can reuse it", async () => {
    const id = (await run(h(), userCreate, { name: "A" })).body.user_id;
    await run(h(), userDisable, { user_id: id });
    const key = randomToken();
    await expect(run(h(), userDisable, { user_id: id }, key)).rejects.toMatchObject({ kind: "state-conflict" });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM idempotency_keys WHERE idempotency_key = ?", key)).toEqual([{ n: 0 }]);
  });

  it("answers a concurrent request with the same key from the winner's stored row", async () => {
    const key = randomToken();
    const outcomes = await Promise.all([run(h(), userCreate, { name: "A" }, key), run(h(), userCreate, { name: "A" }, key)]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 1 }]);
    expect(outcomes[0]?.body).toEqual(outcomes[1]?.body);
  });

  it("replays after losing the primary-key race that the first lookup missed", async () => {
    const key = randomToken();
    const first = await run(h(), userCreate, { name: "A" }, key);
    let lookups = 0;
    const racing: Database = {
      batch: async (statements) => {
        const results = await h().db.batch(statements);
        // Hide the winner's row from the first lookup, as if the two requests had looked up at the same moment.
        if (statements[0]?.sql.startsWith("SELECT operation") === true && lookups++ === 0) return [{ rows: [], changes: 0 }];
        return results;
      },
    };
    const second = await executeOperation({ ...h().ctx(), db: racing }, userCreate, { name: "A" }, { idempotencyKey: key });
    expect(lookups).toBe(2);
    expect(second).toEqual({ status: 201, body: first.body, replayed: true });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM users")).toEqual([{ n: 1 }]);
  });
});

describe("request hashing", () => {
  it("ignores member order and absent members", async () => {
    // The same text as before the RFC 8785 package, so stored request hashes still match.
    expect(await requestHash({ b: 1, a: [{ d: 2, c: "x" }], e: undefined })).toBe(await sha256Base64url('{"a":[{"c":"x","d":2}],"b":1}'));
    expect(await requestHash({ a: 1, b: 2 })).toBe(await requestHash({ b: 2, a: 1 }));
    expect(await requestHash({ a: 1 })).not.toBe(await requestHash({ a: 2 }));
  });
});
