// Scenario 11: the admin Worker's RFC 9421 gate on a real workerd (docs/design/hosting-modes.md 3.8), with the bundle
// and the deployment configuration that ship. A request signed with the allowlisted test-time P-384 key passes;
// unsigned, wrong-key, replayed, expired, and tampered requests get the same 403 and write nothing to D1; and the
// admin Worker's own Rate Limiting binding refuses a client IP over its limit.
import type { D1Database } from "@cloudflare/workers-types";
import { generateTestAdminKey, signAdminRequest, type SignOptions, type TestAdminKey } from "../../apps/admin-worker/test/signer.js";
import { expect, test } from "../support/fixtures.js";
import { ADMIN_HOST, ADMIN_TEST_RATE_LIMIT, type AdminRequestInit, type LocalIdp } from "../support/idp.js";

const USERS = `https://${ADMIN_HOST}/v1/users`;

let ipCounter = 0;

/** A client IP of its own for each request group, so the rate limit of one test never refuses another's. */
function freshIp(): string {
  ipCounter += 1;
  return `198.51.100.${String(ipCounter)}`;
}

type Request = { url: string; init: { method: string; body: string | undefined; headers: Headers } };

async function signed(key: TestAdminKey, ip: string, options: SignOptions = {}): Promise<Request> {
  const body = JSON.stringify({ name: "E2E Admin User" });
  const raw = new Headers({ "content-type": "application/json", "idempotency-key": idempotencyKey(), "cf-connecting-ip": ip });
  const headers = await signAdminRequest({ method: "POST", url: USERS, headers: raw, body: new TextEncoder().encode(body) }, key, options);
  return { url: USERS, init: { method: "POST", body, headers } };
}

function idempotencyKey(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
}

async function counts(db: D1Database): Promise<{ readonly audit: unknown; readonly nonces: unknown; readonly users: unknown }> {
  return {
    audit: await db.prepare("SELECT COUNT(*) AS n FROM audit_log").first("n"),
    nonces: await db.prepare("SELECT COUNT(*) AS n FROM admin_request_nonces").first("n"),
    users: await db.prepare("SELECT COUNT(*) AS n FROM users").first("n"),
  };
}

async function send(idp: LocalIdp, request: Request): Promise<Response> {
  return idp.dispatchAdmin(request.url, request.init as AdminRequestInit);
}

async function expectRefusedWithoutWrites(idp: LocalIdp, request: Request): Promise<void> {
  const before = await counts(idp.db);
  const response = await send(idp, request);
  expect(response.status).toBe(403);
  expect(await response.json()).toEqual({ type: "urn:ojilab:idp:problem:forbidden", title: "Forbidden", status: 403, detail: "Forbidden" });
  expect(await counts(idp.db)).toEqual(before);
}

test("a request signed with the allowlisted P-384 key creates a user and records the admin's keyid", async ({ idp }) => {
  const response = await send(idp, await signed(idp.adminKey, freshIp()));
  expect(response.status).toBe(201);
  const { user_id: userId } = (await response.json()) as { user_id: string };
  const row = await idp.db.prepare("SELECT admin_name, admin_cert_sha256, admin_credential FROM audit_log WHERE target = ?").bind(`user:${userId}`).first();
  expect(row).toEqual({ admin_name: "e2e-admin", admin_cert_sha256: idp.adminKey.keyid, admin_credential: "signing-key" });
});

test("an unsigned request is refused without a D1 write", async ({ idp }) => {
  const request = await signed(idp.adminKey, freshIp());
  for (const name of ["signature", "signature-input", "content-digest"]) request.init.headers.delete(name);
  await expectRefusedWithoutWrites(idp, request);
});

test("a request signed by a key that is not allowlisted is refused without a D1 write", async ({ idp }) => {
  const stranger = await generateTestAdminKey();
  await expectRefusedWithoutWrites(idp, await signed(stranger, freshIp()));
  // Claiming the allowlisted keyid does not help: the allowlisted public key does not verify it.
  await expectRefusedWithoutWrites(idp, await signed(stranger, freshIp(), { keyid: idp.adminKey.keyid }));
});

test("a replayed request is refused without a second D1 write", async ({ idp }) => {
  const request = await signed(idp.adminKey, freshIp());
  expect((await send(idp, request)).status).toBe(201);
  await expectRefusedWithoutWrites(idp, request);
});

test("an expired signature is refused without a D1 write", async ({ idp }) => {
  await expectRefusedWithoutWrites(idp, await signed(idp.adminKey, freshIp(), { created: Math.floor(Date.now() / 1000) - 61 }));
});

test("a request tampered with after signing is refused without a D1 write", async ({ idp }) => {
  const body = await signed(idp.adminKey, freshIp());
  body.init.body = JSON.stringify({ name: "Mallory" });
  await expectRefusedWithoutWrites(idp, body);
  const path = await signed(idp.adminKey, freshIp());
  path.url = `https://${ADMIN_HOST}/v1/groups`;
  await expectRefusedWithoutWrites(idp, path);
});

test("the admin Worker's own rate limit refuses a client IP over its limit", async ({ idp }) => {
  const ip = freshIp();
  // Unsigned requests count too: the limit is taken before the signature is parsed.
  for (let i = 0; i < ADMIN_TEST_RATE_LIMIT; i += 1) {
    expect((await idp.dispatchAdmin(USERS, { headers: new Headers({ "cf-connecting-ip": ip }) })).status).toBe(403);
  }
  const before = await counts(idp.db);
  const limited = await send(idp, await signed(idp.adminKey, ip));
  expect(limited.status).toBe(429);
  expect(await limited.text()).toBe("");
  expect(await counts(idp.db)).toEqual(before);
  // Another client IP is not affected.
  expect((await send(idp, await signed(idp.adminKey, freshIp()))).status).toBe(201);
});
