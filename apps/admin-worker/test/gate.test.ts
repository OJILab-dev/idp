// The checks every request passes before any work (docs/design/hosting-modes.md 3.8; docs/design/idpctl.md,
// "管理者の認証（RFC 9421 の署名）" and "許可リストによる管理者の確定"; docs/design/security-checklist.md, the admin
// Worker). Every refused request is checked to leave D1 untouched: no nonce and no audit row (hosting-modes.md 3.6).
import { describe, expect, it } from "vitest";
import type { Env } from "../src/index.js";
import { ADMIN_BODY_LIMIT_BYTES } from "../src/gate.js";
import { ADMIN_HOST, CLIENT_IP, auditRows, buildRequest, call, expectProblem, idempotent, keys, newKey, nonceCount, send, useFixture, type Fixture } from "./fixture.js";
import { generateTestAdminKey, signingKeysJson } from "./signer.js";

const f = useFixture();

const FORBIDDEN = { type: "urn:ojilab:idp:problem:forbidden", title: "Forbidden", status: 403, detail: "Forbidden" };

async function expectForbiddenWithoutWrites(fx: Fixture, response: Response): Promise<void> {
  const body = await expectProblem(response, "forbidden", 403);
  // One body for every refusal: the response never tells which check failed.
  expect(body).toEqual(FORBIDDEN);
  expect(await auditRows(fx)).toEqual([]);
  expect(await nonceCount(fx)).toBe(0);
}

function createUser(options: Parameters<typeof call>[3] = {}): Promise<Response> {
  return call(f(), "POST", "/v1/users", { body: { name: "Alice" }, headers: idempotent(), ...options });
}

describe("a signed request", () => {
  it("passes with a test-time P-384 key, stores its nonce, and records the admin and keyid", async () => {
    const res = await createUser();
    expect(res.status).toBe(201);
    expect(await nonceCount(f())).toBe(1);
    const [row] = await auditRows(f());
    expect(row).toMatchObject({ actor: "admin", admin_name: "root", admin_cert_sha256: keys().root.keyid, admin_credential: "signing-key", result: "success" });
  });

  it("resolves the admin from the allowlisted key, never from a name the request supplies", async () => {
    const res = await createUser({ signer: keys().other, headers: { ...idempotent(), "x-admin": "root" } });
    expect(res.status).toBe(201);
    const [row] = await auditRows(f());
    expect(row).toMatchObject({ admin_name: "other", admin_cert_sha256: keys().other.keyid });
  });

  it("passes a POST without a body and without Content-Type", async () => {
    const created = (await (await createUser()).json()) as { user_id: string };
    const res = await call(f(), "POST", `/v1/users/${created.user_id}/enrollment-links`, { headers: idempotent() });
    expect(res.status).toBe(201);
  });

  it("verifies @target-uri against request.url, query included", async () => {
    expect((await call(f(), "GET", "/v1/users?limit=1")).status).toBe(200);
  });
});

describe("the signature check (fail-closed, nothing written)", () => {
  it("refuses an unsigned request", async () => {
    await expectForbiddenWithoutWrites(f(), await createUser({ signer: null }));
  });

  it("refuses a request signed by a key that is not allowlisted", async () => {
    await expectForbiddenWithoutWrites(f(), await createUser({ signer: keys().stranger }));
  });

  it("refuses a request that claims an allowlisted keyid but was signed by another key", async () => {
    await expectForbiddenWithoutWrites(f(), await createUser({ signer: keys().stranger, sign: { keyid: keys().root.keyid } }));
  });

  it.each([
    ["61 seconds old", -61],
    ["61 seconds in the future", 61],
  ])("refuses a signature created %s", async (_label, offset) => {
    await expectForbiddenWithoutWrites(f(), await createUser({ sign: { created: Math.floor(Date.now() / 1000) + offset } }));
  });

  it.each([
    ["the body", (r: { body: string | undefined }) => (r.body = JSON.stringify({ name: "Mallory" }))],
    ["the path", (r: { url: string }) => (r.url = r.url.replace("/v1/users", "/v1/groups"))],
    ["the query", (r: { url: string }) => (r.url = `${r.url}?x=1`)],
    ["the method", (r: { method: string }) => (r.method = "PUT")],
    ["the Idempotency-Key", (r: { headers: Headers }) => r.headers.set("idempotency-key", newKey())],
    ["the Content-Type", (r: { headers: Headers }) => r.headers.set("content-type", "application/json; charset=utf-8")],
    ["the signature", (r: { headers: Headers }) => r.headers.set("signature", (r.headers.get("signature") ?? "").replace(/:(.)/, (_m, c: string) => `:${c === "A" ? "B" : "A"}`))],
    ["the Content-Digest and the body together", (r: { headers: Headers; body: string | undefined }) => {
      r.body = JSON.stringify({ name: "Mallory" });
      r.headers.set("content-digest", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    }],
  ] as const)("refuses a request whose %s changed after signing", async (_label, tamper) => {
    await expectForbiddenWithoutWrites(f(), await createUser({ tamper: tamper as (r: unknown) => void }));
  });

  it("refuses the replay of a request that passed, and writes only the first request's rows", async () => {
    const prepared = await buildRequest("POST", "/v1/users", { body: { name: "Alice" }, headers: idempotent() });
    expect((await send(f(), prepared)).status).toBe(201);
    const rows = await auditRows(f());
    const replay = await send(f(), prepared);
    expect(await expectProblem(replay, "forbidden", 403)).toEqual(FORBIDDEN);
    // The replay wrote nothing: the nonce row and the audit row are the first request's.
    expect(await auditRows(f())).toEqual(rows);
    expect(await nonceCount(f())).toBe(1);
  });

  it("refuses before routing, so an unknown path does not reveal itself", async () => {
    await expectForbiddenWithoutWrites(f(), await call(f(), "GET", "/nope", { signer: null }));
  });
});

describe("the TLS version check (fail-closed)", () => {
  // The zone's minimum TLS version belongs to the zone's owner (docs/design/domain-placement.md, 3), so the Worker
  // refuses TLS below 1.2 itself, even for a correctly signed request.
  it.each([
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
    ["an unknown version", { tlsVersion: "TLSv1.4" }],
    ["no tlsVersion", {}],
    ["no request.cf", null],
  ])("refuses %s before the rate limit, the database, or the IdP Worker", async (_label, cf) => {
    await expectForbiddenWithoutWrites(f(), await createUser({ cf }));
    expect(f().limiterKeys).toEqual([]);
  });

  it("accepts TLS 1.2", async () => {
    expect((await call(f(), "GET", "/v1/users", { cf: { tlsVersion: "TLSv1.2" } })).status).toBe(200);
  });
});

describe("the host check", () => {
  it.each([
    ["another host", "https://idp.example.com"],
    ["a workers.dev URL", "https://idp-admin.someone.workers.dev"],
    ["a subdomain of the admin host", `https://x.${ADMIN_HOST}`],
    ["an explicit port", `https://${ADMIN_HOST}:8443`],
    ["plain http", `http://${ADMIN_HOST}`],
  ])("refuses %s, even signed for it, before the rate limit or the database", async (_label, origin) => {
    await expectForbiddenWithoutWrites(f(), await createUser({ origin }));
    expect(f().limiterKeys).toEqual([]);
  });

  // The admin host redirects nothing: idpctl never follows a redirect, and a request that came over plain http has
  // already exposed whatever it carried (docs/design/idpctl.md, "構成").
  it.each(["GET", "HEAD"])("refuses a plain http %s without a redirect", async (method) => {
    const res = await call(f(), method, "/v1/users", { origin: `http://${ADMIN_HOST}` });
    expect(res.status).toBe(403);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("the rate limit (hosting-modes.md 6.2)", () => {
  it("counts every request by its client IP before the signature is parsed, unsigned ones included", async () => {
    await call(f(), "GET", "/v1/users", { signer: null });
    await call(f(), "GET", "/v1/users");
    expect(f().limiterKeys).toEqual([CLIENT_IP, CLIENT_IP]);
  });

  it("refuses a limited request with a bodyless 429 and writes nothing, even when it is correctly signed", async () => {
    f().limiterAnswer = () => ({ success: false });
    const res = await createUser();
    expect(res.status).toBe(429);
    expect(await res.text()).toBe("");
    expect(res.headers.get("retry-after")).toBeNull();
    expect(await auditRows(f())).toEqual([]);
    expect(await nonceCount(f())).toBe(0);
  });

  it("refuses a request without a client IP, which cannot be counted", async () => {
    await expectForbiddenWithoutWrites(f(), await createUser({ clientIp: null }));
    expect(f().limiterKeys).toEqual([]);
  });

  it("refuses with internal when the binding fails, rather than letting the request through uncounted", async () => {
    f().limiterAnswer = () => {
      throw new Error("limiter unavailable");
    };
    await expectProblem(await createUser(), "internal", 500);
    expect(await auditRows(f())).toEqual([]);
    expect(await nonceCount(f())).toBe(0);
  });
});

describe("the body size limit", () => {
  it("refuses a body over the limit before hashing it, even when it is correctly signed", async () => {
    const res = await createUser({ body: { name: "a".repeat(ADMIN_BODY_LIMIT_BYTES) } });
    await expectForbiddenWithoutWrites(f(), res);
  });
});

describe("the nonce store", () => {
  it("refuses with internal, and runs no operation, when the nonce cannot be stored", async () => {
    await f().d1.db.prepare("DROP TABLE admin_request_nonces").run();
    await expectProblem(await createUser(), "internal", 500);
    expect(await auditRows(f())).toEqual([]);
  });
});

describe("the configuration (fail-closed)", () => {
  function root(): Record<string, string> {
    return { keyid: keys().root.keyid, name: "root", public_key: keys().root.publicKey };
  }
  const broken: readonly (readonly [string, () => Partial<Record<keyof Env, unknown>>])[] = [
    ["no signing keys", () => ({ ADMIN_SIGNING_KEYS: undefined })],
    ["signing keys that are not JSON", () => ({ ADMIN_SIGNING_KEYS: "[" })],
    ["an empty signing-key list", () => ({ ADMIN_SIGNING_KEYS: "[]" })],
    ["signing keys as an object", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify({ [keys().root.keyid]: root() }) })],
    ["a row with an extra member", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), alg: "ecdsa-p384-sha384" }]) })],
    ["a row without a name", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), name: undefined }]) })],
    ["an uppercase keyid", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), keyid: keys().root.keyid.toUpperCase() }]) })],
    ["a keyid that is not the SHA-256 of the public key", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), keyid: keys().other.keyid }]) })],
    ["a repeated keyid", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([root(), { ...root(), name: "two" }]) })],
    ["an invalid admin name", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), name: "Root Admin" }]) })],
    ["a public key that is not base64", () => ({ ADMIN_SIGNING_KEYS: JSON.stringify([{ ...root(), public_key: "not base64!" }]) })],
    ["no Rate Limiting binding", () => ({ RATE_LIMITER: undefined })],
    // The hosting and issuer parsers' own branches are tested in the core; these rows prove the wiring.
    ["no hosting mode", () => ({ HOSTING_MODE: undefined })],
    ["the custom_domain mode with a workers.dev admin host", () => ({ ADMIN_HOST: "idp-admin.team.workers.dev" })],
    ["no admin host", () => ({ ADMIN_HOST: undefined })],
    ["an admin host with a port", () => ({ ADMIN_HOST: `${ADMIN_HOST}:443` })],
    ["an admin host equal to the issuer host", () => ({ ADMIN_HOST: "idp.example.com" })],
    ["no issuer", () => ({ ISSUER: undefined })],
    ["no D1 binding", () => ({ DB: undefined })],
    ["no version metadata", () => ({ CF_VERSION_METADATA: undefined })],
    ["an empty version id", () => ({ CF_VERSION_METADATA: { id: "", tag: "", timestamp: "" } })],
  ];

  it.each(broken)("refuses every request when the config has %s", async (_label, overrides) => {
    const env = { ...f().env(), ...overrides() } as Env;
    const body = await expectProblem(await call(f(), "GET", "/v1/users", { env }), "internal", 500);
    expect(body["detail"]).toBe("The request failed; see the admin Worker log");
    // Still refused on the next request: the bad config is not retried into acceptance.
    await expectProblem(await call(f(), "GET", "/v1/users", { env }), "internal", 500);
    expect(await nonceCount(f())).toBe(0);
  });

  it("refuses every request when a public key is not P-384", async () => {
    const p256 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", p256.publicKey)) as ArrayBuffer);
    const keyid = Buffer.from(await crypto.subtle.digest("SHA-256", spki)).toString("hex");
    const env = { ...f().env(), ADMIN_SIGNING_KEYS: JSON.stringify([{ keyid, name: "root", public_key: Buffer.from(spki).toString("base64") }]) } as Env;
    await expectProblem(await call(f(), "GET", "/v1/users", { env }), "internal", 500);
  });

  it("accepts the workers_dev mode with the hosts derived from one subdomain", async () => {
    const env = { ...f().env(), HOSTING_MODE: "workers_dev", ISSUER: "https://idp.team.workers.dev", ADMIN_HOST: "idp-admin.team.workers.dev" } as Env;
    const res = await call(f(), "GET", "/v1/users", { env, origin: "https://idp-admin.team.workers.dev" });
    expect(res.status).toBe(200);
  });

  it("lets one admin hold two keys during a rotation", async () => {
    const next = await generateTestAdminKey();
    const env = { ...f().env(), ADMIN_SIGNING_KEYS: signingKeysJson([["root", keys().root], ["root", next]]) } as Env;
    expect((await call(f(), "GET", "/v1/users", { env, signer: next })).status).toBe(200);
    expect((await call(f(), "GET", "/v1/users", { env })).status).toBe(200);
  });
});
