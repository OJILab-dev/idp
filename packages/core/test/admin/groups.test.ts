import { describe, expect, it } from "vitest";
import { AdminProblem } from "../../src/admin/index.js";
import { groupCreate, groupDisable, groupEnable, groupMemberAdd, groupMemberRemove, groupRename, groupsList } from "../../src/admin/groups.js";
import { userCreate, userDisable } from "../../src/admin/users.js";
import { isUuidV4 } from "../../src/identifiers/index.js";
import { T0, auditRows, effectiveAccess, query, run, seedClient, seedGrant, useHarness } from "./harness.js";

const h = useHarness();
const MISSING = "0f8fad5b-d9cb-469f-a165-70867728950e";

async function createUser(name = "Alice"): Promise<string> {
  return (await run(h(), userCreate, { name })).body.user_id;
}

async function createGroup(name = "family"): Promise<string> {
  return (await run(h(), groupCreate, { name })).body.group_id;
}

async function expectProblem(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error) => error instanceof AdminProblem && error.kind === kind);
}

describe("group_create", () => {
  it("creates an empty, enabled group and audits its ID without its name", async () => {
    const outcome = await run(h(), groupCreate, { name: "family" });
    expect(outcome.status).toBe(201);
    const id = outcome.body.group_id;
    expect(isUuidV4(id)).toBe(true);
    expect(await query(h(), "SELECT kind FROM principals WHERE id = ?", id)).toEqual([{ kind: "group" }]);
    expect(await query(h(), "SELECT enablement FROM group_enablement WHERE group_id = ?", id)).toEqual([{ enablement: "enabled" }]);
    const rows = await auditRows(h());
    expect(rows).toEqual([expect.objectContaining({ operation: "group_create", target: `group:${id}`, detail: {} })]);
    expect(JSON.stringify(rows)).not.toContain("family");
  });

  it("rejects a taken name with already-exists and creates nothing", async () => {
    await createGroup("family");
    await expectProblem(run(h(), groupCreate, { name: "family" }), "already-exists");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM principals")).toEqual([{ n: 1 }]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM group_enablement_events")).toEqual([{ n: 1 }]);
    expect((await auditRows(h()))[1]).toMatchObject({ result: "failure", target: "none", detail: { problem: "already-exists" } });
  });
});

describe("group_rename", () => {
  it("renames without recording the names", async () => {
    const id = await createGroup("family");
    await expect(run(h(), groupRename, { group_id: id, name: "household" }, null)).resolves.toMatchObject({
      body: { group_id: id, name: "household" },
    });
    expect(await query(h(), "SELECT name FROM groups")).toEqual([{ name: "household" }]);
    const rows = await auditRows(h());
    expect(rows[1]).toMatchObject({ operation: "group_rename", target: `group:${id}`, detail: {} });
    expect(JSON.stringify(rows)).not.toMatch(/family|household/);
  });

  it("succeeds without writing for the same name", async () => {
    const id = await createGroup("family");
    await run(h(), groupRename, { group_id: id, name: "family" }, null);
    expect(await auditRows(h())).toHaveLength(1);
  });

  it("rejects a name another group holds", async () => {
    await createGroup("family");
    const other = await createGroup("sales");
    await expectProblem(run(h(), groupRename, { group_id: other, name: "family" }, null), "already-exists");
    expect(await query(h(), "SELECT name FROM groups ORDER BY name")).toEqual([{ name: "family" }, { name: "sales" }]);
  });

  it("is not-found for a missing group", async () => {
    await expectProblem(run(h(), groupRename, { group_id: MISSING, name: "x" }, null), "not-found");
  });
});

describe("group_member_add and group_member_remove", () => {
  it("adds a member and returns and records the newly enabled pairs", async () => {
    const user = await createUser();
    const group = await createGroup();
    await seedClient(h(), "grafana");
    await seedClient(h(), "photos");
    await seedGrant(h(), group, "grafana");
    await seedGrant(h(), group, "photos");
    await seedGrant(h(), user, "photos");
    const outcome = await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    // photos was already allowed directly, so only grafana is new.
    expect(outcome.body).toEqual({ group_id: group, user_id: user, newly_enabled: [{ user_id: user, client_id: "grafana" }] });
    expect(await effectiveAccess(h())).toEqual([`${user} grafana`, `${user} photos`]);
    const row = (await auditRows(h())).at(-1);
    expect(row).toMatchObject({
      operation: "group_member_add",
      target: `group:${group}`,
      detail: { user_id: user, newly_enabled: [{ user_id: user, client_id: "grafana" }] },
    });
  });

  it("records no pairs when the group is disabled, though the membership is added", async () => {
    const user = await createUser();
    const group = await createGroup();
    await seedClient(h(), "grafana");
    await seedGrant(h(), group, "grafana");
    await run(h(), groupDisable, { group_id: group });
    const outcome = await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    expect(outcome.body.newly_enabled).toEqual([]);
    expect(await effectiveAccess(h())).toEqual([]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ detail: { user_id: user, newly_enabled: [] } });
  });

  it("records no pairs for a disabled user", async () => {
    const user = await createUser();
    const group = await createGroup();
    await seedClient(h(), "grafana");
    await seedGrant(h(), group, "grafana");
    await run(h(), userDisable, { user_id: user });
    expect((await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null)).body.newly_enabled).toEqual([]);
  });

  it("succeeds without writing for an existing member", async () => {
    const user = await createUser();
    const group = await createGroup();
    await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    const before = (await auditRows(h())).length;
    await expect(run(h(), groupMemberAdd, { group_id: group, user_id: user }, null)).resolves.toMatchObject({ body: { newly_enabled: [] } });
    expect(await auditRows(h())).toHaveLength(before);
  });

  it("is not-found for a missing group or user", async () => {
    const user = await createUser();
    const group = await createGroup();
    await expectProblem(run(h(), groupMemberAdd, { group_id: MISSING, user_id: user }, null), "not-found");
    await expectProblem(run(h(), groupMemberAdd, { group_id: group, user_id: MISSING }, null), "not-found");
    // A group ID is not a user ID: principals share one namespace, but membership references users only.
    await expectProblem(run(h(), groupMemberAdd, { group_id: group, user_id: group }, null), "not-found");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM group_members")).toEqual([{ n: 0 }]);
  });

  it("removes a member and the access it gave", async () => {
    const user = await createUser();
    const group = await createGroup();
    await seedClient(h(), "grafana");
    await seedGrant(h(), group, "grafana");
    await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    await expect(run(h(), groupMemberRemove, { group_id: group, user_id: user }, null)).resolves.toMatchObject({ status: 200 });
    expect(await effectiveAccess(h())).toEqual([]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ operation: "group_member_remove", target: `group:${group}`, detail: { user_id: user } });
  });

  it("is not-found when removing a membership that does not exist", async () => {
    const user = await createUser();
    const group = await createGroup();
    await expectProblem(run(h(), groupMemberRemove, { group_id: group, user_id: user }, null), "not-found");
    expect((await auditRows(h())).at(-1)).toMatchObject({ result: "failure", target: `group:${group}` });
  });
});

describe("group_disable and group_enable", () => {
  it("stops and restores access through the group, keeping members and grants", async () => {
    const user = await createUser();
    const group = await createGroup();
    await seedClient(h(), "grafana");
    await seedGrant(h(), group, "grafana");
    await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    expect(await effectiveAccess(h())).toEqual([`${user} grafana`]);
    await run(h(), groupDisable, { group_id: group });
    expect(await effectiveAccess(h())).toEqual([]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM group_members")).toEqual([{ n: 1 }]);
    await run(h(), groupEnable, { group_id: group });
    expect(await effectiveAccess(h())).toEqual([`${user} grafana`]);
    const ops = (await auditRows(h())).map((r) => [r["operation"], r["detail"]]);
    expect(ops.slice(-2)).toEqual([
      ["group_disable", { enablement: "disabled" }],
      ["group_enable", { enablement: "enabled" }],
    ]);
  });

  it("rejects the current state with state-conflict, and a missing group with not-found", async () => {
    const group = await createGroup();
    await expectProblem(run(h(), groupEnable, { group_id: group }), "state-conflict");
    await expectProblem(run(h(), groupDisable, { group_id: MISSING }), "not-found");
  });

  it("does not delete sessions of members", async () => {
    const user = await createUser();
    const group = await createGroup();
    await run(h(), groupMemberAdd, { group_id: group, user_id: user }, null);
    await query(
      h(),
      "INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via) VALUES ('c1', ?, x'01', 0, 0, 0, ?, 'enroll')",
      user,
      T0,
    );
    await query(h(), "INSERT INTO sessions (token_hash, user_id, credential_id, auth_time, expires_at) VALUES ('s', ?, 'c1', ?, ?)", user, T0, T0 + 60);
    await run(h(), groupDisable, { group_id: group });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM sessions")).toEqual([{ n: 1 }]);
  });
});

describe("groups_list", () => {
  it("lists groups with state, members, and granted clients", async () => {
    const user = await createUser();
    const a = await createGroup("a");
    h().clock = T0 + 1;
    const b = await createGroup("b");
    await seedClient(h(), "grafana");
    await seedGrant(h(), a, "grafana");
    await run(h(), groupMemberAdd, { group_id: a, user_id: user }, null);
    await run(h(), groupDisable, { group_id: b });
    expect((await run(h(), groupsList, { limit: "10" }, null)).body).toEqual({
      items: [
        { group_id: a, name: "a", enablement: "enabled", created_at: T0, members: [user], clients: ["grafana"] },
        { group_id: b, name: "b", enablement: "disabled", created_at: T0 + 1, members: [], clients: [] },
      ],
      next_cursor: null,
      prev_cursor: null,
    });
  });
});
