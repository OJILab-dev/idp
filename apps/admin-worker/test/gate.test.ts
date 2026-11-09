// The checks every request passes before any work (docs/design/idpctl.md, "管理者の認証（mTLS）" and
// "許可リストによる管理者の確定"; docs/design/security-checklist.md, "管理用の Worker（mTLS）").
import { describe, expect, it } from "vitest";
import type { Env } from "../src/index.js";
import { ADMIN_HOST, OTHER_FP, ROOT_FP, auditRows, call, expectProblem, idempotent, useFixture, verifiedCert } from "./fixture.js";

const f = useFixture();

function tls(overrides: Record<string, unknown>): Record<string, unknown> {
  return { tlsVersion: "TLSv1.3", tlsClientAuth: { certVerified: "SUCCESS", certRevoked: "0", certFingerprintSHA256: ROOT_FP, ...overrides } };
}

describe("the TLS version check (fail-closed)", () => {
  // The zone's minimum TLS version belongs to the zone's owner (docs/design/domain-placement.md, 3), so the Worker
  // refuses TLS below 1.2 itself, even with a valid, allowlisted certificate.
  it.each([
    ["TLS 1.0", { tlsVersion: "TLSv1" }],
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
    ["an unknown version", { tlsVersion: "TLSv1.4" }],
    ["no tlsVersion", { tlsVersion: undefined }],
  ])("refuses %s with forbidden before touching the database or the IdP Worker", async (_label, override) => {
    const res = await call(f(), "POST", "/v1/users", { cf: { ...verifiedCert(), ...override }, body: { name: "Alice" }, headers: idempotent() });
    await expectProblem(res, "forbidden", 403);
    expect(await auditRows(f())).toEqual([]);
    expect(f().idpCalls).toEqual([]);
  });

  it("accepts TLS 1.2", async () => {
    const res = await call(f(), "GET", "/v1/users", { cf: { ...verifiedCert(), tlsVersion: "TLSv1.2" } });
    expect(res.status).toBe(200);
  });
});

describe("the host check", () => {
  it.each([
    ["another host", "https://idp.example.com"],
    ["a workers.dev URL", "https://admin-worker.someone.workers.dev"],
    ["a subdomain of the admin host", `https://x.${ADMIN_HOST}`],
    ["an explicit port", `https://${ADMIN_HOST}:8443`],
    ["plain http", `http://${ADMIN_HOST}`],
  ])("refuses %s with forbidden before touching the database or the IdP Worker", async (_label, origin) => {
    const res = await call(f(), "POST", "/v1/users", { origin, body: { name: "Alice" }, headers: idempotent() });
    await expectProblem(res, "forbidden", 403);
    expect(await auditRows(f())).toEqual([]);
    expect(f().idpCalls).toEqual([]);
  });

  it("accepts the configured host", async () => {
    const res = await call(f(), "GET", "/v1/users");
    expect(res.status).toBe(200);
  });
});

describe("the mTLS re-check (fail-closed)", () => {
  const rejected: readonly (readonly [string, Record<string, unknown> | null])[] = [
    ["no request.cf", null],
    ["no tlsClientAuth", { tlsVersion: "TLSv1.3" }],
    ["tlsClientAuth that is not an object", { tlsVersion: "TLSv1.3", tlsClientAuth: "SUCCESS" }],
    ["no certificate (NONE)", tls({ certVerified: "NONE" })],
    ["a failed verification", tls({ certVerified: "FAILED:self signed certificate" })],
    ["certVerified as a boolean", tls({ certVerified: true })],
    ["certVerified missing", tls({ certVerified: undefined })],
    ["certVerified in another case", tls({ certVerified: "success" })],
    ["a revoked certificate", tls({ certRevoked: "1" })],
    ["certRevoked as a number", tls({ certRevoked: 0 })],
    ["certRevoked as a boolean", tls({ certRevoked: false })],
    ["certRevoked missing", tls({ certRevoked: undefined })],
    ["the fingerprint missing", tls({ certFingerprintSHA256: undefined })],
    ["an empty fingerprint", tls({ certFingerprintSHA256: "" })],
    ["a fingerprint that is not hex", tls({ certFingerprintSHA256: "zz".repeat(32) })],
    ["a short fingerprint", tls({ certFingerprintSHA256: ROOT_FP.slice(1) })],
    ["a fingerprint with colons", tls({ certFingerprintSHA256: ROOT_FP.match(/../g)?.join(":") })],
    ["a fingerprint with whitespace", tls({ certFingerprintSHA256: ` ${ROOT_FP}` })],
    ["an unknown fingerprint", tls({ certFingerprintSHA256: "ef".repeat(32) })],
  ];

  it.each(rejected)("refuses %s with forbidden and no reason", async (_label, cf) => {
    const res = await call(f(), "GET", "/v1/users", { cf });
    const body = await expectProblem(res, "forbidden", 403);
    expect(body).toEqual({ type: "urn:ojilab:idp:problem:forbidden", title: "Forbidden", status: 403, detail: "Forbidden" });
  });

  it("writes no audit row for a refused write", async () => {
    const res = await call(f(), "POST", "/v1/users", { cf: tls({ certRevoked: "1" }), body: { name: "Alice" }, headers: idempotent() });
    await expectProblem(res, "forbidden", 403);
    expect(await auditRows(f())).toEqual([]);
  });

  it("refuses before routing, so an unknown path does not reveal itself", async () => {
    const res = await call(f(), "GET", "/nope", { cf: null });
    await expectProblem(res, "forbidden", 403);
  });

  it("normalises an uppercase fingerprint to the allowlist's lowercase hex", async () => {
    const res = await call(f(), "POST", "/v1/users", { cf: verifiedCert(OTHER_FP.toUpperCase()), body: { name: "Alice" }, headers: idempotent() });
    expect(res.status).toBe(201);
    const [row] = await auditRows(f());
    expect(row).toMatchObject({ admin_name: "other", admin_cert_sha256: OTHER_FP });
  });

  it("records the admin the allowlist resolved, never a name the request supplies", async () => {
    const res = await call(f(), "POST", "/v1/users", { body: { name: "Alice" }, headers: { ...idempotent(), "x-admin": "mallory" } });
    expect(res.status).toBe(201);
    const [row] = await auditRows(f());
    expect(row).toMatchObject({ actor: "admin", admin_name: "root", admin_cert_sha256: ROOT_FP, result: "success" });
  });
});

describe("the configuration (fail-closed)", () => {
  const broken: readonly (readonly [string, Record<string, unknown>])[] = [
    ["no allowlist", { ADMIN_ALLOWLIST: undefined }],
    ["an allowlist that is not JSON", { ADMIN_ALLOWLIST: "{" }],
    ["an empty allowlist", { ADMIN_ALLOWLIST: "[]" }],
    ["an allowlist that is an object", { ADMIN_ALLOWLIST: JSON.stringify({ [ROOT_FP]: "root" }) }],
    ["an uppercase fingerprint", { ADMIN_ALLOWLIST: JSON.stringify([{ sha256: ROOT_FP.toUpperCase(), name: "root" }]) }],
    ["a short fingerprint", { ADMIN_ALLOWLIST: JSON.stringify([{ sha256: "ab", name: "root" }]) }],
    ["a repeated fingerprint", { ADMIN_ALLOWLIST: JSON.stringify([{ sha256: ROOT_FP, name: "root" }, { sha256: ROOT_FP, name: "two" }]) }],
    ["an invalid admin name", { ADMIN_ALLOWLIST: JSON.stringify([{ sha256: ROOT_FP, name: "Root Admin" }]) }],
    ["an extra member", { ADMIN_ALLOWLIST: JSON.stringify([{ sha256: ROOT_FP, name: "root", cn: "root" }]) }],
    ["no admin host", { ADMIN_HOST: undefined }],
    ["an admin host with a port", { ADMIN_HOST: `${ADMIN_HOST}:443` }],
    ["an uppercase admin host", { ADMIN_HOST: ADMIN_HOST.toUpperCase() }],
    ["an admin host that is a URL", { ADMIN_HOST: `https://${ADMIN_HOST}` }],
    ["an admin host equal to the issuer host", { ADMIN_HOST: "idp.example.com" }],
    ["no issuer", { ISSUER: undefined }],
    ["an issuer with a path", { ISSUER: "https://idp.example.com/" }],
    ["no D1 binding", { DB: undefined }],
    ["no version metadata", { CF_VERSION_METADATA: undefined }],
    ["an empty version id", { CF_VERSION_METADATA: { id: "", tag: "", timestamp: "" } }],
  ];

  it.each(broken)("refuses every request when the config has %s", async (_label, overrides) => {
    const env = { ...f().env(), ...overrides } as Env;
    const res = await call(f(), "GET", "/v1/users", { env });
    const body = await expectProblem(res, "internal", 500);
    expect(body["detail"]).toBe("The request failed; see the admin Worker log");
    // Still refused on the next request: the bad config is not retried into acceptance.
    await expectProblem(await call(f(), "GET", "/v1/users", { env }), "internal", 500);
  });
});
