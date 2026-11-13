import { describe, expect, it } from "vitest";
import { AdminProblem } from "../../src/domain/index.js";
import { clientCreate, clientDisable } from "../../src/domain/clients.js";
import { accessCheck, grantAdd, grantRemove, grantsList } from "../../src/domain/grants.js";
import { groupCreate, groupDisable, groupMemberAdd } from "../../src/domain/groups.js";
import { userCreate, userDisable } from "../../src/domain/users.js";
import { T0, auditRows, effectiveAccess, query, run, useHarness } from "./harness.js";

const h = useHarness();
const MISSING = "0f8fad5b-d9cb-469f-a165-70867728950e";

async function expectProblem(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error) => error instanceof AdminProblem && error.kind === kind);
}

async function setup(): Promise<{ readonly alice: string; readonly bob: string; readonly family: string }> {
  const alice = (await run(h(), userCreate, { name: "Alice" })).body.user_id;
  const bob = (await run(h(), userCreate, { name: "Bob" })).body.user_id;
  const family = (await run(h(), groupCreate, { name: "family" })).body.group_id;
  await run(h(), groupMemberAdd, { group_id: family, user_id: alice }, null);
  await run(h(), groupMemberAdd, { group_id: family, user_id: bob }, null);
  await run(h(), clientCreate, { client_id: "photos", name: "Photos", client_type: "public", redirect_uris: ["http://127.0.0.1/cb"] });
  return { alice, bob, family };
}

describe("grant_add", () => {
  it("grants a group and returns and records every member newly enabled", async () => {
    const { alice, bob, family } = await setup();
    const outcome = await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    const pairs = [alice, bob].sort().map((user_id) => ({ user_id, client_id: "photos" }));
    expect(outcome.body).toEqual({ client_id: "photos", principal: `group:${family}`, newly_enabled: pairs });
    expect(await effectiveAccess(h())).toEqual(pairs.map((p) => `${p.user_id} photos`));
    expect((await auditRows(h())).at(-1)).toMatchObject({
      operation: "grant_add",
      target: "client:photos",
      detail: { principal: `group:${family}`, newly_enabled: pairs },
    });
  });

  it("leaves out pairs already allowed and disabled members", async () => {
    const { alice, bob, family } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null);
    await run(h(), userDisable, { user_id: bob });
    const outcome = await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    expect(outcome.body.newly_enabled).toEqual([]);
  });

  it("enables nothing through a disabled group or for a disabled client, but still writes the grant", async () => {
    const { alice, family } = await setup();
    await run(h(), groupDisable, { group_id: family });
    expect((await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null)).body.newly_enabled).toEqual([]);
    await run(h(), clientDisable, { client_id: "photos" });
    expect((await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null)).body.newly_enabled).toEqual([]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM client_access")).toEqual([{ n: 2 }]);
    expect(await effectiveAccess(h())).toEqual([]);
  });

  it("succeeds without writing for an existing grant", async () => {
    const { alice } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null);
    const before = (await auditRows(h())).length;
    await expect(run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null)).resolves.toMatchObject({
      body: { newly_enabled: [] },
    });
    expect(await auditRows(h())).toHaveLength(before);
  });

  it("is not-found for a missing client, a missing principal, or a prefix that does not match the principal's kind", async () => {
    const { alice, family } = await setup();
    await expectProblem(run(h(), grantAdd, { client_id: "nope", principal: `user:${alice}` }, null), "not-found");
    await expectProblem(run(h(), grantAdd, { client_id: "photos", principal: `user:${MISSING}` }, null), "not-found");
    await expectProblem(run(h(), grantAdd, { client_id: "photos", principal: `user:${family}` }, null), "not-found");
    await expectProblem(run(h(), grantAdd, { client_id: "photos", principal: `group:${alice}` }, null), "not-found");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM client_access")).toEqual([{ n: 0 }]);
  });

  it.each(["family", "user:Alice", `team:${MISSING}`, `user:${MISSING}:x`])("rejects the principal %j by format, never by name", async (principal) => {
    await setup();
    await expect(run(h(), grantAdd, { client_id: "photos", principal }, null)).rejects.toMatchObject({ kind: "validation-failed", pointers: ["/principal"] });
    expect(JSON.stringify((await auditRows(h())).at(-1))).not.toContain(principal);
  });
});

describe("grant_remove", () => {
  it("removes a grant and the access it gave", async () => {
    const { alice } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null);
    await run(h(), grantRemove, { client_id: "photos", principal: `user:${alice}` }, null);
    expect(await effectiveAccess(h())).toEqual([]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ operation: "grant_remove", target: "client:photos", detail: { principal: `user:${alice}` } });
  });

  it("is not-found for a grant that does not exist or is named with the wrong prefix", async () => {
    const { alice, family } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    await expectProblem(run(h(), grantRemove, { client_id: "photos", principal: `user:${alice}` }, null), "not-found");
    await expectProblem(run(h(), grantRemove, { client_id: "photos", principal: `user:${family}` }, null), "not-found");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM client_access")).toEqual([{ n: 1 }]);
  });
});

describe("grants_list", () => {
  it("lists grants in creation order and filters by client and principal", async () => {
    const { alice, family } = await setup();
    await run(h(), clientCreate, { client_id: "wiki", name: "Wiki", client_type: "public", redirect_uris: ["http://127.0.0.1/cb"] });
    await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    h().clock = T0 + 1;
    await run(h(), grantAdd, { client_id: "wiki", principal: `user:${alice}` }, null);
    expect((await run(h(), grantsList, {}, null)).body.items).toEqual([
      { principal: `group:${family}`, client_id: "photos", created_at: T0 },
      { principal: `user:${alice}`, client_id: "wiki", created_at: T0 + 1 },
    ]);
    expect((await run(h(), grantsList, { client_id: "wiki" }, null)).body.items).toHaveLength(1);
    expect((await run(h(), grantsList, { principal: `group:${family}` }, null)).body.items).toHaveLength(1);
    expect((await run(h(), grantsList, { principal: `user:${family}` }, null)).body.items).toHaveLength(0);
  });

  it("pages over grants that share a creation time", async () => {
    const { alice, bob } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null);
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${bob}` }, null);
    const first = await run(h(), grantsList, { limit: 1 }, null);
    const second = await run(h(), grantsList, { limit: 1, cursor: first.body.next_cursor }, null);
    expect([first.body.items[0]?.principal, second.body.items[0]?.principal].sort()).toEqual([`user:${alice}`, `user:${bob}`].sort());
    expect(second.body.next_cursor).toBeNull();
  });
});

describe("access_check", () => {
  it("explains a direct grant and a group grant", async () => {
    const { alice, family } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${alice}` }, null);
    await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    expect((await run(h(), accessCheck, { user: alice, client: "photos" }, null)).body).toEqual({
      user_id: alice,
      client_id: "photos",
      allowed: true,
      user_enablement: "enabled",
      client_enablement: "enabled",
      grants: [
        { via: "direct", principal: `user:${alice}`, counts: true },
        { via: "group", principal: `group:${family}`, group_enablement: "enabled", counts: true },
      ],
      denied_because: [],
    });
  });

  it("says what is missing: no grant, a disabled group, a disabled user, a disabled client", async () => {
    const { alice, bob, family } = await setup();
    expect((await run(h(), accessCheck, { user: alice, client: "photos" }, null)).body).toMatchObject({ allowed: false, denied_because: ["no-grant"] });
    await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    await run(h(), groupDisable, { group_id: family });
    expect((await run(h(), accessCheck, { user: alice, client: "photos" }, null)).body).toMatchObject({
      allowed: false,
      grants: [{ via: "group", group_enablement: "disabled", counts: false }],
      denied_because: ["group-disabled"],
    });
    await run(h(), grantAdd, { client_id: "photos", principal: `user:${bob}` }, null);
    await run(h(), userDisable, { user_id: bob });
    await run(h(), clientDisable, { client_id: "photos" });
    expect((await run(h(), accessCheck, { user: bob, client: "photos" }, null)).body).toMatchObject({
      allowed: false,
      user_enablement: "disabled",
      client_enablement: "disabled",
      denied_because: ["user-disabled", "client-disabled"],
    });
  });

  it("agrees with effective_access for every user and client", async () => {
    const { alice, bob, family } = await setup();
    await run(h(), grantAdd, { client_id: "photos", principal: `group:${family}` }, null);
    await run(h(), userDisable, { user_id: bob });
    const allowed = await effectiveAccess(h());
    for (const user of [alice, bob]) {
      const result = await run(h(), accessCheck, { user, client: "photos" }, null);
      expect(result.body.allowed).toBe(allowed.includes(`${user} photos`));
    }
  });

  it("is not-found for a missing user or client and writes no audit row", async () => {
    const { alice } = await setup();
    const before = (await auditRows(h())).length;
    await expectProblem(run(h(), accessCheck, { user: MISSING, client: "photos" }, null), "not-found");
    await expectProblem(run(h(), accessCheck, { user: alice, client: "nope" }, null), "not-found");
    expect(await auditRows(h())).toHaveLength(before);
  });
});
