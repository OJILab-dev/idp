import { describe, expect, it } from "vitest";
import { AdminProblem } from "../../src/admin/index.js";
import {
  clientCreate,
  clientDisable,
  clientEnable,
  clientRename,
  clientRotateSecret,
  clientSetIdTokenAlg,
  clientSetPostLogoutRedirects,
  clientSetRedirects,
  clientsList,
} from "../../src/admin/clients.js";
import { userCreate } from "../../src/admin/users.js";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isRandomTokenFormat, randomToken } from "../../src/identifiers/index.js";
import { T0, auditRows, effectiveAccess, query, run, seedGrant, useHarness } from "./harness.js";

const h = useHarness();

const WEB = { client_id: "grafana", name: "Grafana", client_type: "confidential", redirect_uris: ["https://grafana.example.com/login"] } as const;
const CLI = { client_id: "my-cli", name: "CLI", client_type: "public", redirect_uris: ["http://127.0.0.1/callback", "com.example.cli:/cb"] } as const;

async function expectProblem(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error) => error instanceof AdminProblem && error.kind === kind);
}

async function secretHash(id: string): Promise<unknown> {
  return (await query(h(), "SELECT secret_hash FROM clients WHERE id = ?", id))[0]?.["secret_hash"];
}

describe("client_create", () => {
  it("registers a confidential client, returns its secret once, and stores only the hash", async () => {
    const outcome = await run(h(), clientCreate, WEB);
    expect(outcome.status).toBe(201);
    const secret = outcome.body.client_secret ?? "";
    expect(isRandomTokenFormat(secret)).toBe(true);
    expect(await secretHash("grafana")).toBe(await sha256Base64url(secret));
    expect(await query(h(), "SELECT name, client_type, redirect_uris_json, id_token_signed_response_alg, created_at FROM clients")).toEqual([
      {
        name: "Grafana",
        client_type: "confidential",
        redirect_uris_json: '["https://grafana.example.com/login"]',
        id_token_signed_response_alg: "Ed25519",
        created_at: T0,
      },
    ]);
    expect(await query(h(), "SELECT enablement FROM client_enablement")).toEqual([{ enablement: "enabled" }]);
    const rows = await auditRows(h());
    expect(rows).toEqual([
      expect.objectContaining({
        operation: "client_create",
        target: "client:grafana",
        detail: { client_type: "confidential", id_token_alg: "Ed25519", redirect_uris: ["https://grafana.example.com/login"] },
      }),
    ]);
    // Neither the secret, its hash, nor the display name reaches the audit log or the idempotency row.
    const logged = JSON.stringify([rows, await query(h(), "SELECT * FROM idempotency_keys")]);
    expect(logged).not.toContain(secret);
    expect(logged).not.toContain(String(await secretHash("grafana")));
    expect(logged).not.toContain("Grafana");
  });

  it("keeps no replayable response for a confidential client: replay is secret-not-replayable", async () => {
    const key = randomToken();
    await run(h(), clientCreate, WEB, key);
    expect(await query(h(), "SELECT replayable, response_json FROM idempotency_keys")).toEqual([{ replayable: 0, response_json: null }]);
    await expectProblem(run(h(), clientCreate, WEB, key), "secret-not-replayable");
  });

  it("registers a public client without a secret, and its response is replayable", async () => {
    const key = randomToken();
    const outcome = await run(h(), clientCreate, CLI, key);
    expect(outcome.body).toEqual({ client_id: "my-cli", client_type: "public" });
    expect(await secretHash("my-cli")).toBeNull();
    await expect(run(h(), clientCreate, CLI, key)).resolves.toMatchObject({ replayed: true, body: outcome.body });
  });

  it("rejects an existing client ID with already-exists, and adds no event to the existing client", async () => {
    await run(h(), clientCreate, WEB);
    await expectProblem(run(h(), clientCreate, { ...WEB, name: "Other" }), "already-exists");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM client_enablement_events")).toEqual([{ n: 1 }]);
    expect((await auditRows(h()))[1]).toMatchObject({ result: "failure", target: "client:grafana", detail: { problem: "already-exists" } });
  });

  it.each([
    ["a loopback URI for a confidential client", { ...WEB, redirect_uris: ["http://127.0.0.1/cb"] }, ["/redirect_uris/0"]],
    ["a custom scheme for a confidential client", { ...WEB, redirect_uris: ["https://a.example.com/cb", "com.example.app:/cb"] }, ["/redirect_uris/1"]],
    ["localhost", { ...CLI, redirect_uris: ["http://localhost/cb"] }, ["/redirect_uris/0"]],
    ["a fragment", { ...CLI, redirect_uris: ["https://a.example.com/cb#x"] }, ["/redirect_uris/0"]],
    ["no URIs", { ...CLI, redirect_uris: [] }, ["/redirect_uris"]],
    ["a repeated URI", { ...CLI, redirect_uris: ["http://127.0.0.1/cb", "http://127.0.0.1/cb"] }, ["/redirect_uris"]],
    ["eleven URIs", { ...CLI, redirect_uris: Array.from({ length: 11 }, (_, i) => `https://a.example.com/${i}`) }, ["/redirect_uris"]],
    ["a malformed client ID", { ...CLI, client_id: "My App" }, ["/client_id"]],
  ])("rejects %s with validation-failed", async (_case, input, pointers) => {
    await expect(run(h(), clientCreate, input)).rejects.toMatchObject({ kind: "validation-failed", pointers });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM clients")).toEqual([{ n: 0 }]);
  });

  it("rejects RS256 when the deployment has not enabled it, and accepts it when it has", async () => {
    await expectProblem(run(h(), clientCreate, { ...WEB, id_token_alg: "RS256" }), "algorithm-disabled");
    expect((await auditRows(h()))[0]).toMatchObject({ result: "failure", target: "client:grafana", detail: { problem: "algorithm-disabled" } });
    h().rs256Enabled = true;
    await run(h(), clientCreate, { ...WEB, id_token_alg: "RS256" });
    expect(await query(h(), "SELECT id_token_signed_response_alg AS alg FROM clients")).toEqual([{ alg: "RS256" }]);
  });
});

describe("client_rename", () => {
  it("renames without recording names, and the same name is a no-op", async () => {
    await run(h(), clientCreate, CLI);
    await run(h(), clientRename, { client_id: "my-cli", name: "Renamed" }, null);
    await run(h(), clientRename, { client_id: "my-cli", name: "Renamed" }, null);
    const rows = await auditRows(h());
    expect(rows.map((r) => r["operation"])).toEqual(["client_create", "client_rename"]);
    expect(rows[1]).toMatchObject({ detail: {} });
    expect(JSON.stringify(rows)).not.toMatch(/Renamed|"CLI"/);
  });

  it("is not-found for a missing client", async () => {
    await expectProblem(run(h(), clientRename, { client_id: "nope", name: "x" }, null), "not-found");
  });
});

describe("client_set_redirects", () => {
  it("replaces the list and records the new URIs", async () => {
    await run(h(), clientCreate, CLI);
    const uris = ["https://cli.example.com/cb", "http://[::1]/cb"];
    await expect(run(h(), clientSetRedirects, { client_id: "my-cli", redirect_uris: uris }, null)).resolves.toMatchObject({
      body: { client_id: "my-cli", redirect_uris: uris },
    });
    expect(await query(h(), "SELECT redirect_uris_json FROM clients")).toEqual([{ redirect_uris_json: JSON.stringify(uris) }]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ operation: "client_set_redirects", detail: { redirect_uris: uris } });
  });

  it("succeeds without writing for the same list", async () => {
    await run(h(), clientCreate, CLI);
    await run(h(), clientSetRedirects, { client_id: "my-cli", redirect_uris: [...CLI.redirect_uris] }, null);
    expect(await auditRows(h())).toHaveLength(1);
  });

  it("applies the client type's rules: a confidential client keeps https only", async () => {
    await run(h(), clientCreate, WEB);
    await expect(
      run(h(), clientSetRedirects, { client_id: "grafana", redirect_uris: ["https://g.example.com/cb", "http://127.0.0.1/cb"] }, null),
    ).rejects.toMatchObject({ kind: "validation-failed", pointers: ["/redirect_uris/1"] });
    expect(await query(h(), "SELECT redirect_uris_json FROM clients")).toEqual([{ redirect_uris_json: JSON.stringify(WEB.redirect_uris) }]);
  });

  it("is not-found for a missing client", async () => {
    await expectProblem(run(h(), clientSetRedirects, { client_id: "nope", redirect_uris: ["https://a.example.com/cb"] }, null), "not-found");
    expect((await auditRows(h()))[0]).toMatchObject({ result: "failure", target: "client:nope" });
  });
});

describe("post_logout_redirect_uris on client_create", () => {
  it("stores an empty list and records nothing when omitted", async () => {
    await run(h(), clientCreate, WEB);
    expect(await query(h(), "SELECT post_logout_redirect_uris_json AS uris FROM clients")).toEqual([{ uris: "[]" }]);
    expect((await auditRows(h()))[0]?.["detail"]).not.toHaveProperty("post_logout_redirect_uris");
  });

  it("stores and records the given list", async () => {
    const uris = ["https://grafana.example.com/bye"];
    await run(h(), clientCreate, { ...WEB, post_logout_redirect_uris: uris });
    expect(await query(h(), "SELECT post_logout_redirect_uris_json AS uris FROM clients")).toEqual([{ uris: JSON.stringify(uris) }]);
    expect((await auditRows(h()))[0]).toMatchObject({ detail: { post_logout_redirect_uris: uris } });
  });

  it("refuses a loopback URI even for a public client", async () => {
    await expect(run(h(), clientCreate, { ...CLI, post_logout_redirect_uris: ["http://127.0.0.1/bye"] })).rejects.toMatchObject({
      kind: "validation-failed",
      pointers: ["/post_logout_redirect_uris/0"],
    });
  });
});

describe("client_set_post_logout_redirects", () => {
  it("replaces the list and records the new URIs", async () => {
    await run(h(), clientCreate, CLI);
    const uris = ["https://cli.example.com/bye", "https://cli.example.com/bye?x=1"];
    await expect(run(h(), clientSetPostLogoutRedirects, { client_id: "my-cli", post_logout_redirect_uris: uris }, null)).resolves.toMatchObject({
      status: 200,
      body: { client_id: "my-cli", post_logout_redirect_uris: uris },
    });
    expect(await query(h(), "SELECT post_logout_redirect_uris_json AS uris FROM clients")).toEqual([{ uris: JSON.stringify(uris) }]);
    expect((await auditRows(h())).at(-1)).toMatchObject({
      operation: "client_set_post_logout_redirects",
      target: "client:my-cli",
      detail: { post_logout_redirect_uris: uris },
    });
  });

  it("accepts an empty list, which stops post-logout redirects", async () => {
    await run(h(), clientCreate, { ...WEB, post_logout_redirect_uris: ["https://grafana.example.com/bye"] });
    await run(h(), clientSetPostLogoutRedirects, { client_id: "grafana", post_logout_redirect_uris: [] }, null);
    expect(await query(h(), "SELECT post_logout_redirect_uris_json AS uris FROM clients")).toEqual([{ uris: "[]" }]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ detail: { post_logout_redirect_uris: [] } });
  });

  it("succeeds without writing for the same list", async () => {
    await run(h(), clientCreate, WEB);
    await run(h(), clientSetPostLogoutRedirects, { client_id: "grafana", post_logout_redirect_uris: [] }, null);
    expect(await auditRows(h())).toHaveLength(1);
  });

  it.each([
    ["a loopback URI", ["http://127.0.0.1/bye"], ["/post_logout_redirect_uris/0"]],
    ["a custom scheme", ["https://a.example.com/bye", "com.example.app:/bye"], ["/post_logout_redirect_uris/1"]],
    ["plain http", ["http://a.example.com/bye"], ["/post_logout_redirect_uris/0"]],
    ["a fragment", ["https://a.example.com/bye#x"], ["/post_logout_redirect_uris/0"]],
    ["userinfo", ["https://u@a.example.com/bye"], ["/post_logout_redirect_uris/0"]],
    ["a non-canonical URI", ["https://A.example.com/bye"], ["/post_logout_redirect_uris/0"]],
    ["localhost", ["https://localhost/bye"], ["/post_logout_redirect_uris/0"]],
    ["its own state parameter", ["https://a.example.com/bye", "https://a.example.com/bye?x=1&state=fixed"], ["/post_logout_redirect_uris/1"]],
    ["a repeated URI", ["https://a.example.com/bye", "https://a.example.com/bye"], ["/post_logout_redirect_uris"]],
    ["eleven URIs", Array.from({ length: 11 }, (_, i) => `https://a.example.com/${i}`), ["/post_logout_redirect_uris"]],
  ])("rejects %s with validation-failed and keeps the list", async (_case, uris, pointers) => {
    await run(h(), clientCreate, CLI);
    await expect(run(h(), clientSetPostLogoutRedirects, { client_id: "my-cli", post_logout_redirect_uris: uris }, null)).rejects.toMatchObject({
      kind: "validation-failed",
      pointers,
    });
    expect(await query(h(), "SELECT post_logout_redirect_uris_json AS uris FROM clients")).toEqual([{ uris: "[]" }]);
  });

  it("is not-found for a missing client", async () => {
    await expectProblem(
      run(h(), clientSetPostLogoutRedirects, { client_id: "nope", post_logout_redirect_uris: ["https://a.example.com/bye"] }, null),
      "not-found",
    );
    expect((await auditRows(h()))[0]).toMatchObject({ result: "failure", target: "client:nope" });
  });
});

describe("client_rotate_secret", () => {
  it("replaces the secret hash and returns the new secret once", async () => {
    const first = (await run(h(), clientCreate, WEB)).body.client_secret;
    const rotated = await run(h(), clientRotateSecret, { client_id: "grafana" });
    expect(rotated.status).toBe(201);
    expect(rotated.body.client_secret).not.toBe(first);
    expect(await secretHash("grafana")).toBe(await sha256Base64url(rotated.body.client_secret));
    expect((await auditRows(h())).at(-1)).toMatchObject({ operation: "client_rotate_secret", target: "client:grafana", detail: {} });
    expect(JSON.stringify(await auditRows(h()))).not.toContain(rotated.body.client_secret);
  });

  it("answers a replay with secret-not-replayable, so the old secret cannot be handed out twice", async () => {
    await run(h(), clientCreate, WEB);
    const key = randomToken();
    await run(h(), clientRotateSecret, { client_id: "grafana" }, key);
    const hash = await secretHash("grafana");
    await expectProblem(run(h(), clientRotateSecret, { client_id: "grafana" }, key), "secret-not-replayable");
    expect(await secretHash("grafana")).toBe(hash);
  });

  it("is state-conflict for a public client and not-found for a missing one", async () => {
    await run(h(), clientCreate, CLI);
    await expectProblem(run(h(), clientRotateSecret, { client_id: "my-cli" }), "state-conflict");
    await expectProblem(run(h(), clientRotateSecret, { client_id: "nope" }), "not-found");
    expect(await secretHash("my-cli")).toBeNull();
  });
});

describe("client_set_id_token_alg", () => {
  it("switches the algorithm and records both values", async () => {
    h().rs256Enabled = true;
    await run(h(), clientCreate, WEB);
    await run(h(), clientSetIdTokenAlg, { client_id: "grafana", id_token_alg: "RS256" }, null);
    expect((await auditRows(h())).at(-1)).toMatchObject({ detail: { previous_id_token_alg: "Ed25519", id_token_alg: "RS256" } });
    await run(h(), clientSetIdTokenAlg, { client_id: "grafana", id_token_alg: "Ed25519" }, null);
    expect((await auditRows(h())).at(-1)).toMatchObject({ detail: { previous_id_token_alg: "RS256", id_token_alg: "Ed25519" } });
  });

  it("succeeds without writing for the same algorithm", async () => {
    await run(h(), clientCreate, WEB);
    await run(h(), clientSetIdTokenAlg, { client_id: "grafana", id_token_alg: "Ed25519" }, null);
    expect(await auditRows(h())).toHaveLength(1);
  });

  it("rejects RS256 while it is disabled, and a missing client with not-found", async () => {
    await run(h(), clientCreate, WEB);
    await expectProblem(run(h(), clientSetIdTokenAlg, { client_id: "grafana", id_token_alg: "RS256" }, null), "algorithm-disabled");
    await expectProblem(run(h(), clientSetIdTokenAlg, { client_id: "nope", id_token_alg: "Ed25519" }, null), "not-found");
  });
});

describe("client_disable and client_enable", () => {
  it("stops and restores access while keeping grants and redirect URIs", async () => {
    await run(h(), clientCreate, WEB);
    const user = (await run(h(), userCreate, { name: "A" })).body.user_id;
    await seedGrant(h(), user, "grafana");
    await run(h(), clientDisable, { client_id: "grafana" });
    expect(await effectiveAccess(h())).toEqual([]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM client_access")).toEqual([{ n: 1 }]);
    await expectProblem(run(h(), clientDisable, { client_id: "grafana" }), "state-conflict");
    await run(h(), clientEnable, { client_id: "grafana" });
    expect(await effectiveAccess(h())).toEqual([`${user} grafana`]);
    await expectProblem(run(h(), clientEnable, { client_id: "nope" }), "not-found");
  });
});

describe("clients_list", () => {
  it("lists clients with their settings and filters by algorithm", async () => {
    h().rs256Enabled = true;
    await run(h(), clientCreate, { ...WEB, id_token_alg: "RS256", post_logout_redirect_uris: ["https://grafana.example.com/bye"] });
    h().clock = T0 + 1;
    await run(h(), clientCreate, CLI);
    await run(h(), clientDisable, { client_id: "my-cli" });
    const all = await run(h(), clientsList, {}, null);
    expect(all.body.items).toEqual([
      {
        client_id: "grafana",
        name: "Grafana",
        client_type: "confidential",
        enablement: "enabled",
        redirect_uris: [...WEB.redirect_uris],
        post_logout_redirect_uris: ["https://grafana.example.com/bye"],
        id_token_alg: "RS256",
        created_at: T0,
      },
      {
        client_id: "my-cli",
        name: "CLI",
        client_type: "public",
        enablement: "disabled",
        redirect_uris: [...CLI.redirect_uris],
        post_logout_redirect_uris: [],
        id_token_alg: "Ed25519",
        created_at: T0 + 1,
      },
    ]);
    const rs256 = await run(h(), clientsList, { id_token_alg: "RS256" }, null);
    expect(rs256.body.items.map((c) => c.client_id)).toEqual(["grafana"]);
    // No secret material is listed.
    expect(JSON.stringify(all.body)).not.toMatch(/secret/);
  });
});
