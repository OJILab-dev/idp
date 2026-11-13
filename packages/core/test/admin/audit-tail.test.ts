import { describe, expect, it } from "vitest";
import { auditTail } from "../../src/admin/audit-tail.js";
import { userCreate, userDisable } from "../../src/admin/users.js";
import { auditSuccessStatement } from "../../src/audit/index.js";
import { ROOT, T0, run, useHarness } from "./harness.js";

const h = useHarness();

async function seedLog(): Promise<{ readonly alice: string; readonly bob: string }> {
  const alice = (await run(h(), userCreate, { name: "Alice" })).body.user_id;
  h().clock = T0 + 10;
  const bob = (await run(h(), userCreate, { name: "Bob" })).body.user_id;
  h().clock = T0 + 20;
  await run(h(), userDisable, { user_id: alice });
  await expect(run(h(), userDisable, { user_id: alice })).rejects.toThrow();
  // The IdP Worker's row for a passkey the user added themselves.
  await h().db.batch([
    auditSuccessStatement({
      occurredAt: T0 + 30,
      actor: { kind: "user" },
      writerVersion: "worker@test",
      operation: "passkey_add",
      target: `user:${bob}`,
      detail: { credential_id: "AAEC" },
    }),
  ]);
  return { alice, bob };
}

describe("audit_tail", () => {
  it("returns every row newest first, admin and user rows alike, with detail parsed", async () => {
    const { alice, bob } = await seedLog();
    const page = await run(h(), auditTail, {}, null);
    expect(page.body.items.map((e) => [e.id, e.operation, e.result])).toEqual([
      [5, "passkey_add", "success"],
      [4, "user_disable", "failure"],
      [3, "user_disable", "success"],
      [2, "user_create", "success"],
      [1, "user_create", "success"],
    ]);
    expect(page.body.items[0]).toEqual({
      id: 5,
      occurred_at: T0 + 30,
      actor: "user",
      admin_name: null,
      admin_cert_sha256: null,
      writer_version: "worker@test",
      operation: "passkey_add",
      target: `user:${bob}`,
      result: "success",
      detail: { credential_id: "AAEC" },
    });
    expect(page.body.items[2]).toMatchObject({ admin_name: ROOT.name, admin_cert_sha256: ROOT.keyid, target: `user:${alice}` });
  });

  it("filters by target, operation, and a half-open time range", async () => {
    const { alice } = await seedLog();
    const byTarget = await run(h(), auditTail, { target: `user:${alice}` }, null);
    expect(byTarget.body.items.map((e) => e.id)).toEqual([4, 3, 1]);
    const byOperation = await run(h(), auditTail, { operation: "user_create" }, null);
    expect(byOperation.body.items.map((e) => e.id)).toEqual([2, 1]);
    const byTime = await run(h(), auditTail, { since: String(T0 + 10), until: T0 + 30 }, null);
    expect(byTime.body.items.map((e) => e.id)).toEqual([4, 3, 2]);
  });

  it("pages from newest to oldest and back", async () => {
    await seedLog();
    const p1 = await run(h(), auditTail, { limit: 2 }, null);
    expect(p1.body.items.map((e) => e.id)).toEqual([5, 4]);
    const p2 = await run(h(), auditTail, { limit: 2, cursor: p1.body.next_cursor }, null);
    expect(p2.body.items.map((e) => e.id)).toEqual([3, 2]);
    const p3 = await run(h(), auditTail, { limit: 2, cursor: p2.body.next_cursor }, null);
    expect(p3.body.items.map((e) => e.id)).toEqual([1]);
    expect(p3.body.next_cursor).toBeNull();
    const back = await run(h(), auditTail, { limit: 2, cursor: p3.body.prev_cursor }, null);
    expect(back.body.items.map((e) => e.id)).toEqual([3, 2]);
  });

  it("is itself not audited", async () => {
    await seedLog();
    await run(h(), auditTail, {}, null);
    expect((await run(h(), auditTail, {}, null)).body.items).toHaveLength(5);
  });

  it.each([
    [{ target: "user:Alice" }, "/target"],
    [{ operation: "User Create" }, "/operation"],
    [{ since: "-1" }, "/since"],
    [{ until: 1.5 }, "/until"],
  ])("rejects %j", async (input, pointer) => {
    await expect(run(h(), auditTail, input, null)).rejects.toMatchObject({ kind: "validation-failed", pointers: [pointer] });
  });
});
