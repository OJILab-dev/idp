import { describe, expect, it } from "vitest";
import { AdminProblem, findOperation } from "../../src/admin/index.js";
import { sessionRevoke, userCreate, userDisable, userEnable, userGet, userRename, usersList } from "../../src/admin/users.js";
import { isUuidV4 } from "../../src/shared/index.js";
import { ROOT, T0, auditRows, effectiveAccess, query, run, seedClient, seedGrant, seedPasskey, seedSession, useHarness } from "./harness.js";

const h = useHarness();
const MISSING = "0f8fad5b-d9cb-469f-a165-70867728950e";

async function createUser(name = "Alice"): Promise<string> {
  return (await run(h(), userCreate, { name })).body.user_id;
}

async function expectProblem(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error) => error instanceof AdminProblem && error.kind === kind);
}

describe("user_create", () => {
  it("creates the principal, the user, and the first enabled event, and audits the new ID", async () => {
    const outcome = await run(h(), userCreate, { name: "Alice" });
    expect(outcome.status).toBe(201);
    const id = outcome.body.user_id;
    expect(isUuidV4(id)).toBe(true);
    expect(await query(h(), "SELECT kind FROM principals WHERE id = ?", id)).toEqual([{ kind: "user" }]);
    const [user] = await query(h(), "SELECT name, created_at, length(user_handle) AS handle FROM users WHERE id = ?", id);
    expect(user).toEqual({ name: "Alice", created_at: T0, handle: 64 });
    expect(await query(h(), "SELECT enablement FROM user_enablement WHERE user_id = ?", id)).toEqual([{ enablement: "enabled" }]);
    const [row] = await auditRows(h());
    expect(row).toMatchObject({
      actor: "admin",
      admin_name: ROOT.name,
      admin_cert_sha256: ROOT.keyid,
      admin_credential: "signing-key",
      writer_version: "admin-worker@test",
      operation: "user_create",
      target: `user:${id}`,
      result: "success",
      detail: {},
    });
  });

  it.each([[""], [" Alice"], ["Alice "], ["a".repeat(65)], ["Ali\u0000ce"], ["Ali ce"], ["é"], [42]])(
    "rejects the name %j with validation-failed at /name and a failure row targeting none",
    async (name) => {
      await expect(run(h(), userCreate, { name })).rejects.toMatchObject({ kind: "validation-failed", pointers: ["/name"] });
      const rows = await auditRows(h());
      expect(rows).toEqual([expect.objectContaining({ operation: "user_create", result: "failure", target: "none", detail: { problem: "validation-failed" } })]);
    },
  );

  it("accepts a 64-code-point name outside the BMP", async () => {
    await expect(run(h(), userCreate, { name: "😀".repeat(64) })).resolves.toMatchObject({ status: 201 });
  });

  it("rejects unknown members", async () => {
    await expect(run(h(), userCreate, { name: "Alice", email: "a@example.com" })).rejects.toMatchObject({ kind: "validation-failed" });
  });
});

describe("user_rename", () => {
  it("renames, and the audit row records neither name", async () => {
    const id = await createUser("Alice Example");
    const outcome = await run(h(), userRename, { user_id: id, name: "Neutral" }, null);
    expect(outcome.body).toEqual({ user_id: id, name: "Neutral" });
    expect(await query(h(), "SELECT name FROM users WHERE id = ?", id)).toEqual([{ name: "Neutral" }]);
    const rows = await auditRows(h());
    expect(rows[1]).toMatchObject({ operation: "user_rename", target: `user:${id}`, result: "success", detail: {} });
    const all = JSON.stringify(rows);
    expect(all).not.toContain("Alice");
    expect(all).not.toContain("Neutral");
  });

  it("succeeds without writing when the name is unchanged", async () => {
    const id = await createUser("Alice");
    await expect(run(h(), userRename, { user_id: id, name: "Alice" }, null)).resolves.toMatchObject({ status: 200 });
    expect(await auditRows(h())).toHaveLength(1);
  });

  it("is not-found for a missing user, with a failure row naming the validated ID", async () => {
    await expectProblem(run(h(), userRename, { user_id: MISSING, name: "Bob" }, null), "not-found");
    expect(await auditRows(h())).toEqual([expect.objectContaining({ result: "failure", target: `user:${MISSING}`, detail: { problem: "not-found" } })]);
  });

  it("names the validated ID as the failure target even when another field fails validation", async () => {
    await expectProblem(run(h(), userRename, { user_id: MISSING, name: "" }, null), "validation-failed");
    expect(await auditRows(h())).toEqual([expect.objectContaining({ target: `user:${MISSING}` })]);
  });

  it("writes none as the failure target when the ID is malformed, and never the malformed value", async () => {
    await expectProblem(run(h(), userRename, { user_id: "Alice Example", name: "Bob" }, null), "validation-failed");
    const rows = await auditRows(h());
    expect(rows).toEqual([expect.objectContaining({ target: "none" })]);
    expect(JSON.stringify(rows)).not.toContain("Alice");
  });
});

describe("user_disable and user_enable", () => {
  it("disables, deletes every session of the user only, and records the deleted count", async () => {
    const alice = await createUser("Alice");
    const bob = await createUser("Bob");
    const aliceKey = await seedPasskey(h(), alice);
    const bobKey = await seedPasskey(h(), bob);
    await seedSession(h(), alice, aliceKey);
    await seedSession(h(), alice, aliceKey);
    await seedSession(h(), bob, bobKey);
    h().clock = T0 + 10;
    const outcome = await run(h(), userDisable, { user_id: alice });
    expect(outcome).toEqual({ status: 201, body: { id: alice, enablement: "disabled", occurred_at: T0 + 10 }, replayed: false });
    expect(await query(h(), "SELECT user_id FROM sessions")).toEqual([{ user_id: bob }]);
    expect(await query(h(), "SELECT enablement FROM user_enablement WHERE user_id = ?", alice)).toEqual([{ enablement: "disabled" }]);
    const rows = await auditRows(h());
    expect(rows[2]).toMatchObject({ operation: "user_disable", target: `user:${alice}`, detail: { enablement: "disabled", sessions_deleted: 2 } });
  });

  it("rejects disabling a disabled user with state-conflict and appends nothing", async () => {
    const id = await createUser();
    await run(h(), userDisable, { user_id: id });
    await expectProblem(run(h(), userDisable, { user_id: id }), "state-conflict");
    expect(await query(h(), "SELECT enablement FROM user_enablement_events WHERE user_id = ? ORDER BY id", id)).toEqual([
      { enablement: "enabled" },
      { enablement: "disabled" },
    ]);
    const rows = await auditRows(h());
    expect(rows.map((r) => `${String(r["operation"])}:${String(r["result"])}`)).toEqual([
      "user_create:success",
      "user_disable:success",
      "user_disable:failure",
    ]);
  });

  it("rejects enabling an enabled user with state-conflict", async () => {
    const id = await createUser();
    await expectProblem(run(h(), userEnable, { user_id: id }), "state-conflict");
  });

  it("re-enables a disabled user", async () => {
    const id = await createUser();
    await run(h(), userDisable, { user_id: id });
    await expect(run(h(), userEnable, { user_id: id })).resolves.toMatchObject({ body: { enablement: "enabled" } });
    expect(await query(h(), "SELECT enablement FROM user_enablement WHERE user_id = ?", id)).toEqual([{ enablement: "enabled" }]);
  });

  it("is not-found for a missing user", async () => {
    await expectProblem(run(h(), userDisable, { user_id: MISSING }), "not-found");
    await expectProblem(run(h(), userEnable, { user_id: MISSING }), "not-found");
  });

  it("removes and restores the user's effective access", async () => {
    const id = await createUser();
    await seedClient(h(), "grafana");
    await seedGrant(h(), id, "grafana");
    expect(await effectiveAccess(h())).toEqual([`${id} grafana`]);
    await run(h(), userDisable, { user_id: id });
    expect(await effectiveAccess(h())).toEqual([]);
    await run(h(), userEnable, { user_id: id });
    expect(await effectiveAccess(h())).toEqual([`${id} grafana`]);
  });
});

describe("session_revoke", () => {
  it("deletes every session of the user and records the count", async () => {
    const id = await createUser();
    const key = await seedPasskey(h(), id);
    await seedSession(h(), id, key);
    await seedSession(h(), id, key);
    const outcome = await run(h(), sessionRevoke, { user_id: id }, null);
    expect(outcome.body).toEqual({ user_id: id, sessions_deleted: 2 });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM sessions")).toEqual([{ n: 0 }]);
    expect((await auditRows(h()))[1]).toMatchObject({ operation: "session_revoke", detail: { sessions_deleted: 2 } });
  });

  it("succeeds with zero sessions and still writes the audit row", async () => {
    const id = await createUser();
    await expect(run(h(), sessionRevoke, { user_id: id }, null)).resolves.toMatchObject({ body: { sessions_deleted: 0 } });
    expect((await auditRows(h()))[1]).toMatchObject({ operation: "session_revoke", result: "success", detail: { sessions_deleted: 0 } });
  });

  it("is not-found for a missing user", async () => {
    await expectProblem(run(h(), sessionRevoke, { user_id: MISSING }, null), "not-found");
  });

  it("keeps the user enabled", async () => {
    const id = await createUser();
    await run(h(), sessionRevoke, { user_id: id }, null);
    expect(await query(h(), "SELECT enablement FROM user_enablement WHERE user_id = ?", id)).toEqual([{ enablement: "enabled" }]);
  });
});

describe("users_list and user_get", () => {
  it("lists users in creation order with state and passkey count, and writes no audit row", async () => {
    const a = await createUser("A");
    h().clock = T0 + 1;
    const b = await createUser("B");
    await seedPasskey(h(), b);
    await run(h(), userDisable, { user_id: a });
    const before = (await auditRows(h())).length;
    const page = await run(h(), usersList, {}, null);
    expect(page.body).toEqual({
      items: [
        { user_id: a, name: "A", enablement: "disabled", created_at: T0, passkey_count: 0 },
        { user_id: b, name: "B", enablement: "enabled", created_at: T0 + 1, passkey_count: 1 },
      ],
      next_cursor: null,
      prev_cursor: null,
    });
    expect(await auditRows(h())).toHaveLength(before);
  });

  it("gets one user with their passkeys", async () => {
    const id = await createUser("A");
    const key = await seedPasskey(h(), id);
    const outcome = await run(h(), userGet, { user_id: id }, null);
    expect(outcome.body).toEqual({
      user_id: id,
      name: "A",
      enablement: "enabled",
      created_at: T0,
      passkeys: [
        { credential_id: key, created_at: T0, last_used_at: null, created_via: "enroll", backup_eligible: true, backup_state: false },
      ],
    });
  });

  it("is not-found for a missing user, without an audit row", async () => {
    await expectProblem(run(h(), userGet, { user_id: MISSING }, null), "not-found");
    expect(await auditRows(h())).toEqual([]);
  });

  it("registers the operations by name", () => {
    expect(findOperation("user_get")).toBe(userGet);
  });
});
