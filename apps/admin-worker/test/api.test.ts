// The REST mapping of docs/design/idpctl.md ("管理 API の形"), run end to end against a local D1: each endpoint
// calls one core operation, and problems, Idempotency-Key, paging, and secrets pass through unchanged.
import { describe, expect, it } from "vitest";
import type { Env } from "../src/index.js";
import { ROUTES } from "../src/routes.js";
import { auditRows, call, discovery, expectProblem, idempotent, newKey, useFixture, type Fixture } from "./fixture.js";

const f = useFixture();

async function createUser(fx: Fixture, name = "Alice"): Promise<string> {
  const res = await call(fx, "POST", "/v1/users", { body: { name }, headers: idempotent() });
  expect(res.status).toBe(201);
  return ((await res.json()) as { user_id: string }).user_id;
}

async function createGroup(fx: Fixture, name = "Family"): Promise<string> {
  const res = await call(fx, "POST", "/v1/groups", { body: { name }, headers: idempotent() });
  expect(res.status).toBe(201);
  return ((await res.json()) as { group_id: string }).group_id;
}

async function createClient(fx: Fixture, body: Record<string, unknown> = {}): Promise<Response> {
  return call(fx, "POST", "/v1/clients", {
    body: { client_id: "grafana", name: "Grafana", client_type: "public", redirect_uris: ["https://grafana.example.com/cb"], ...body },
    headers: idempotent(),
  });
}

describe("the route table", () => {
  it("exposes every operation exactly once, enable and disable through one enablement-events endpoint", () => {
    const names = ROUTES.flatMap((r) => r.operations.map((o) => o.name)).sort();
    expect(names).toHaveLength(29);
    expect(new Set(names).size).toBe(29);
    expect(ROUTES).toHaveLength(26);
    const switches = ROUTES.filter((r) => r.operations.length === 2)
      .map((r) => [r.operationId, r.method, r.path, r.operations.map((o) => o.name).sort()])
      .sort();
    expect(switches).toEqual([
      ["client_enablement_switch", "POST", "/v1/clients/{id}/enablement-events", ["client_disable", "client_enable"]],
      ["group_enablement_switch", "POST", "/v1/groups/{id}/enablement-events", ["group_disable", "group_enable"]],
      ["user_enablement_switch", "POST", "/v1/users/{id}/enablement-events", ["user_disable", "user_enable"]],
    ]);
  });

  it("gives every other endpoint the operation name as its operationId", () => {
    for (const route of ROUTES.filter((r) => r.operations.length === 1)) expect(route.operationId).toBe(route.operations[0]?.name);
  });
});

describe("users", () => {
  it("creates, reads, renames, and lists users", async () => {
    const id = await createUser(f());
    const got = await call(f(), "GET", `/v1/users/${id}`);
    expect(got.status).toBe(200);
    expect(await got.json()).toMatchObject({ user_id: id, name: "Alice", enablement: "enabled" });

    const renamed = await call(f(), "PUT", `/v1/users/${id}/name`, { body: { name: "Alicia" } });
    expect(renamed.status).toBe(200);
    expect(await renamed.json()).toEqual({ user_id: id, name: "Alicia" });

    const list = await call(f(), "GET", "/v1/users");
    expect(await list.json()).toMatchObject({ items: [{ user_id: id, name: "Alicia" }], next_cursor: null, prev_cursor: null });
  });

  it("pages with limit and the cursor the previous page returned", async () => {
    // The list order is (created_at, ID), and the creations may or may not share a second, so the expected order is
    // the one an unpaged list returns.
    for (const name of ["A", "B", "C"]) await createUser(f(), name);
    const all = (await (await call(f(), "GET", "/v1/users")).json()) as { items: { user_id: string }[] };
    const ids = all.items.map((u) => u.user_id);
    expect(ids).toHaveLength(3);
    const first = (await (await call(f(), "GET", "/v1/users?limit=2")).json()) as { items: { user_id: string }[]; next_cursor: string };
    expect(first.items.map((u) => u.user_id)).toEqual(ids.slice(0, 2));
    const second = await call(f(), "GET", `/v1/users?limit=2&cursor=${encodeURIComponent(first.next_cursor)}`);
    const page = (await second.json()) as { items: { user_id: string }[]; next_cursor: string | null; prev_cursor: string | null };
    expect(page.items.map((u) => u.user_id)).toEqual(ids.slice(2));
    expect(page.next_cursor).toBeNull();
    expect(page.prev_cursor).toEqual(expect.any(String));
  });

  it("validates query parameters with the core's schema", async () => {
    const body = await expectProblem(await call(f(), "GET", "/v1/users?limit=0"), "validation-failed", 400);
    expect(body["errors"]).toEqual(["/limit"]);
    const cursor = await expectProblem(await call(f(), "GET", "/v1/users?cursor=bad!"), "validation-failed", 400);
    expect(cursor["errors"]).toEqual(["/cursor"]);
    const unknown = await expectProblem(await call(f(), "GET", "/v1/users?offset=10"), "validation-failed", 400);
    expect(unknown["errors"]).toEqual([""]);
  });

  it("rejects a repeated query parameter", async () => {
    const body = await expectProblem(await call(f(), "GET", "/v1/users?limit=1&limit=2"), "validation-failed", 400);
    expect(body["errors"]).toEqual(["/limit"]);
  });

  it("validates path IDs, and answers not-found for an unknown user", async () => {
    const bad = await expectProblem(await call(f(), "GET", "/v1/users/alice"), "validation-failed", 400);
    expect(bad["errors"]).toEqual(["/user_id"]);
    await expectProblem(await call(f(), "GET", `/v1/users/${crypto.randomUUID()}`), "not-found", 404);
  });

  it("disables and enables through enablement-events, recording the real operation names", async () => {
    const id = await createUser(f());
    const disabled = await call(f(), "POST", `/v1/users/${id}/enablement-events`, { body: { enablement: "disabled" }, headers: idempotent() });
    expect(disabled.status).toBe(201);
    expect(await disabled.json()).toMatchObject({ id, enablement: "disabled" });
    await expectProblem(
      await call(f(), "POST", `/v1/users/${id}/enablement-events`, { body: { enablement: "disabled" }, headers: idempotent() }),
      "state-conflict",
      409,
    );
    const enabled = await call(f(), "POST", `/v1/users/${id}/enablement-events`, { body: { enablement: "enabled" }, headers: idempotent() });
    expect(enabled.status).toBe(201);
    const rows = await auditRows(f());
    expect(rows.map((r) => [r["operation"], r["result"]])).toEqual([
      ["user_create", "success"],
      ["user_disable", "success"],
      ["user_disable", "failure"],
      ["user_enable", "success"],
    ]);
  });

  it("rejects an enablement body outside the schema", async () => {
    const id = await createUser(f());
    const body = await expectProblem(
      await call(f(), "POST", `/v1/users/${id}/enablement-events`, { body: { enablement: "on" }, headers: idempotent() }),
      "validation-failed",
      400,
    );
    expect(body["errors"]).toEqual(["/enablement"]);
  });

  it("issues an enrollment link once and never replays it", async () => {
    const id = await createUser(f());
    const key = newKey();
    const res = await call(f(), "POST", `/v1/users/${id}/enrollment-links`, { headers: idempotent(key) });
    expect(res.status).toBe(201);
    const link = (await res.json()) as { enrollment_link: string };
    expect(link.enrollment_link).toMatch(/^https:\/\/idp\.example\.com\/enroll#[A-Za-z0-9_-]{43}$/);
    await expectProblem(await call(f(), "POST", `/v1/users/${id}/enrollment-links`, { headers: idempotent(key) }), "secret-not-replayable", 409);
  });

  it("revokes sessions and answers not-found for an unknown passkey", async () => {
    const id = await createUser(f());
    const res = await call(f(), "DELETE", `/v1/users/${id}/sessions`);
    expect(res.status).toBe(200);
    await expectProblem(await call(f(), "DELETE", `/v1/users/${id}/passkeys/AAAA`), "not-found", 404);
  });

  it("refuses to revoke the last passkey", async () => {
    const id = await createUser(f());
    await f()
      .d1.db.prepare(
        "INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via) VALUES ('AAAA', ?, x'01', 0, 1, 0, 0, 'enroll')",
      )
      .bind(id)
      .run();
    await expectProblem(await call(f(), "DELETE", `/v1/users/${id}/passkeys/AAAA`), "last-passkey", 409);
  });
});

describe("Idempotency-Key", () => {
  it("is required on a creating POST", async () => {
    await expectProblem(await call(f(), "POST", "/v1/users", { body: { name: "Alice" } }), "validation-failed", 400);
    await expectProblem(await call(f(), "POST", "/v1/users", { body: { name: "Alice" }, headers: { "idempotency-key": "short" } }), "validation-failed", 400);
  });

  it("replays the stored response for the same key and body, and refuses a different body", async () => {
    const key = newKey();
    const first = await call(f(), "POST", "/v1/users", { body: { name: "Alice" }, headers: idempotent(key) });
    const again = await call(f(), "POST", "/v1/users", { body: { name: "Alice" }, headers: idempotent(key) });
    expect(again.status).toBe(first.status);
    expect(await again.json()).toEqual(await first.json());
    await expectProblem(await call(f(), "POST", "/v1/users", { body: { name: "Bob" }, headers: idempotent(key) }), "idempotency-key-reused", 422);
  });

  it("does not let the same key replay across users of an enablement event", async () => {
    const alice = await createUser(f(), "Alice");
    const bob = await createUser(f(), "Bob");
    const key = newKey();
    const first = await call(f(), "POST", `/v1/users/${alice}/enablement-events`, { body: { enablement: "disabled" }, headers: idempotent(key) });
    expect(first.status).toBe(201);
    await expectProblem(
      await call(f(), "POST", `/v1/users/${bob}/enablement-events`, { body: { enablement: "disabled" }, headers: idempotent(key) }),
      "idempotency-key-reused",
      422,
    );
  });
});

describe("request bodies", () => {
  it("rejects a body that is not JSON and records the failure", async () => {
    const id = await createUser(f());
    const res = await call(f(), "PUT", `/v1/users/${id}/name`, { rawBody: "{", headers: { "content-type": "application/json" } });
    const body = await expectProblem(res, "validation-failed", 400);
    expect(body["errors"]).toEqual([""]);
    const rows = await auditRows(f());
    expect(rows.at(-1)).toMatchObject({ operation: "user_rename", result: "failure", target: `user:${id}` });
  });

  it("rejects a JSON body that is not an object", async () => {
    const id = await createUser(f());
    await expectProblem(await call(f(), "PUT", `/v1/users/${id}/name`, { body: ["Alicia"] }), "validation-failed", 400);
  });

  it("rejects a body that is not application/json", async () => {
    const id = await createUser(f());
    const res = await call(f(), "PUT", `/v1/users/${id}/name`, { rawBody: JSON.stringify({ name: "x" }), headers: { "content-type": "text/plain" } });
    await expectProblem(res, "validation-failed", 400);
  });

  it("does not let the body name a different target than the path", async () => {
    const alice = await createUser(f(), "Alice");
    const bob = await createUser(f(), "Bob");
    const body = await expectProblem(
      await call(f(), "PUT", `/v1/users/${alice}/name`, { body: { name: "Eve", user_id: bob } }),
      "validation-failed",
      400,
    );
    expect(body["errors"]).toEqual(["/user_id"]);
  });
});

describe("prototype keys", () => {
  it.each(["__proto__", "constructor", "prototype"])("rejects a body member named %s and records the failure", async (key) => {
    const alice = await createUser(f(), "Alice");
    const bob = await createUser(f(), "Bob");
    // A raw body, since JSON.stringify of an object literal would not emit __proto__ as an own member.
    const rawBody = `{"name":"Eve","${key}":{"user_id":"${bob}"}}`;
    const res = await call(f(), "PUT", `/v1/users/${alice}/name`, { rawBody, headers: { "content-type": "application/json" } });
    const body = await expectProblem(res, "validation-failed", 400);
    expect(body["errors"]).toEqual([`/${key}`]);
    const rows = await auditRows(f());
    expect(rows.at(-1)).toMatchObject({ operation: "user_rename", result: "failure", target: `user:${alice}` });
    const got = (await (await call(f(), "GET", `/v1/users/${alice}`)).json()) as { name: string };
    expect(got.name).toBe("Alice");
  });

  it("rejects __proto__ in an enablement-events body", async () => {
    const id = await createUser(f());
    const rawBody = `{"enablement":"disabled","__proto__":{"enablement":"enabled"}}`;
    const res = await call(f(), "POST", `/v1/users/${id}/enablement-events`, { rawBody, headers: { "content-type": "application/json", ...idempotent() } });
    const body = await expectProblem(res, "validation-failed", 400);
    expect(body["errors"]).toEqual(["/__proto__"]);
  });

  it.each(["__proto__", "constructor", "prototype"])("rejects a query parameter named %s", async (key) => {
    const body = await expectProblem(await call(f(), "GET", `/v1/users?${key}=x`), "validation-failed", 400);
    expect(body["errors"]).toEqual([`/${key}`]);
  });

  it("treats __proto__ as a path value like any other invalid ID", async () => {
    const body = await expectProblem(await call(f(), "GET", "/v1/users/__proto__"), "validation-failed", 400);
    expect(body["errors"]).toEqual(["/user_id"]);
    const grant = await expectProblem(await call(f(), "PUT", "/v1/clients/grafana/grants/__proto__"), "validation-failed", 400);
    expect(grant["errors"]).toEqual(["/principal"]);
  });
});

describe("clients", () => {
  it("returns a confidential client's secret once and refuses to replay it", async () => {
    const key = newKey();
    const body = { client_id: "grafana", name: "Grafana", client_type: "confidential", redirect_uris: ["https://grafana.example.com/cb"] };
    const res = await call(f(), "POST", "/v1/clients", { body, headers: idempotent(key) });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ client_id: "grafana", client_type: "confidential", client_secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
    await expectProblem(await call(f(), "POST", "/v1/clients", { body, headers: idempotent(key) }), "secret-not-replayable", 409);

    const rotated = await call(f(), "POST", "/v1/clients/grafana/secrets", { headers: idempotent() });
    expect(rotated.status).toBe(201);
    expect(await rotated.json()).toMatchObject({ client_id: "grafana", client_secret: expect.any(String) });
  });

  it("renames, sets redirect URIs, lists, and disables a client", async () => {
    expect((await createClient(f())).status).toBe(201);
    expect((await call(f(), "PUT", "/v1/clients/grafana/name", { body: { name: "Dashboards" } })).status).toBe(200);
    const redirects = await call(f(), "PUT", "/v1/clients/grafana/redirect-uris", { body: { redirect_uris: ["https://g.example.com/cb"] } });
    expect(redirects.status).toBe(200);
    const list = (await (await call(f(), "GET", "/v1/clients?id_token_alg=Ed25519")).json()) as { items: { client_id: string }[] };
    expect(list.items.map((c) => c.client_id)).toEqual(["grafana"]);
    const disabled = await call(f(), "POST", "/v1/clients/grafana/enablement-events", { body: { enablement: "disabled" }, headers: idempotent() });
    expect(disabled.status).toBe(201);
  });

  describe("RS256 enablement from the IdP Worker's discovery", () => {
    it("refuses RS256 when discovery does not list it", async () => {
      await expectProblem(await createClient(f(), { id_token_alg: "RS256" }), "algorithm-disabled", 409);
      expect(f().idpCalls).toEqual(["https://idp.example.com/.well-known/openid-configuration"]);
    });

    it("accepts RS256 when discovery lists it", async () => {
      f().idpResponse = () => discovery(["EdDSA", "RS256"]);
      expect((await createClient(f(), { id_token_alg: "RS256" })).status).toBe(201);
      const set = await call(f(), "PUT", "/v1/clients/grafana/id-token-alg", { body: { id_token_alg: "Ed25519" } });
      expect(set.status).toBe(200);
    });

    it.each([
      ["a failing IdP Worker", () => new Response("down", { status: 503 })],
      ["a body that is not JSON", () => new Response("<html>", { status: 200 })],
      ["a different issuer", () => Response.json({ issuer: "https://evil.example.com", id_token_signing_alg_values_supported: ["RS256"] })],
      ["a list that is not an array", () => Response.json({ issuer: "https://idp.example.com", id_token_signing_alg_values_supported: "RS256" })],
      [
        "a thrown fetch",
        () => {
          throw new Error("unreachable");
        },
      ],
    ])("treats %s as RS256 disabled (fail-closed)", async (_label, response) => {
      expect((await createClient(f())).status).toBe(201);
      f().idpResponse = response;
      await expectProblem(await call(f(), "PUT", "/v1/clients/grafana/id-token-alg", { body: { id_token_alg: "RS256" } }), "algorithm-disabled", 409);
    });

    it("treats a missing IdP binding as RS256 disabled", async () => {
      const env = { ...f().env(), IDP: undefined } as unknown as Env;
      const res = await call(f(), "POST", "/v1/clients", {
        env,
        body: { client_id: "grafana", name: "G", client_type: "public", redirect_uris: ["https://g.example.com/cb"], id_token_alg: "RS256" },
        headers: idempotent(),
      });
      await expectProblem(res, "algorithm-disabled", 409);
    });

    it("does not ask the IdP Worker for operations that cannot name an algorithm", async () => {
      await createUser(f());
      expect(f().idpCalls).toEqual([]);
    });
  });
});

describe("groups, grants, and access", () => {
  it("adds members and grants by path, then explains access", async () => {
    const user = await createUser(f());
    const group = await createGroup(f());
    expect((await createClient(f())).status).toBe(201);
    expect((await call(f(), "PUT", `/v1/groups/${group}/name`, { body: { name: "Kin" } })).status).toBe(200);
    expect((await call(f(), "PUT", `/v1/groups/${group}/members/${user}`)).status).toBe(200);

    const grant = await call(f(), "PUT", `/v1/clients/grafana/grants/group:${group}`);
    expect(grant.status).toBe(200);
    expect(await grant.json()).toMatchObject({ client_id: "grafana", principal: `group:${group}`, newly_enabled: [{ user_id: user, client_id: "grafana" }] });

    const access = await call(f(), "GET", `/v1/access?user=${user}&client=grafana`);
    expect(access.status).toBe(200);
    expect(await access.json()).toMatchObject({ allowed: true });

    const grants = (await (await call(f(), "GET", "/v1/grants?client_id=grafana")).json()) as { items: unknown[] };
    expect(grants.items).toHaveLength(1);
    const groups = (await (await call(f(), "GET", "/v1/groups")).json()) as { items: unknown[] };
    expect(groups.items).toHaveLength(1);

    expect((await call(f(), "DELETE", `/v1/clients/grafana/grants/group:${group}`)).status).toBe(200);
    expect((await call(f(), "DELETE", `/v1/groups/${group}/members/${user}`)).status).toBe(200);
    await expectProblem(await call(f(), "DELETE", `/v1/groups/${group}/members/${user}`), "not-found", 404);
    const disabled = await call(f(), "POST", `/v1/groups/${group}/enablement-events`, { body: { enablement: "disabled" }, headers: idempotent() });
    expect(disabled.status).toBe(201);
  });

  it("rejects a principal that is not user:<id> or group:<id>", async () => {
    expect((await createClient(f())).status).toBe(201);
    const body = await expectProblem(await call(f(), "PUT", "/v1/clients/grafana/grants/alice"), "validation-failed", 400);
    expect(body["errors"]).toEqual(["/principal"]);
  });
});

describe("audit events", () => {
  it("lists the rows newest first with the admin the allowlist resolved", async () => {
    await createUser(f());
    const res = await call(f(), "GET", "/v1/audit-events?operation=user_create&since=0");
    const page = (await res.json()) as { items: Record<string, unknown>[] };
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({ operation: "user_create", admin_name: "root", writer_version: "admin-worker@00000000-0000-4000-8000-0000000000aa" });
  });
});

describe("everything else", () => {
  it("answers not-found for an unknown path or method", async () => {
    await expectProblem(await call(f(), "GET", "/v1/nope"), "not-found", 404);
    await expectProblem(await call(f(), "PATCH", "/v1/users"), "not-found", 404);
    await expectProblem(await call(f(), "GET", "/v1/users/"), "not-found", 404);
  });

  it("answers internal without details when the database fails", async () => {
    const broken = {
      prepare: () => ({ bind: () => ({}) }),
      batch: () => Promise.reject(new Error("SQLITE_BUSY: secret detail")),
    } as unknown as D1Database;
    const env = { ...f().env(), DB: broken };
    const body = await expectProblem(await call(f(), "GET", "/v1/users", { env }), "internal", 500);
    expect(JSON.stringify(body)).not.toContain("SQLITE");
  });
});
