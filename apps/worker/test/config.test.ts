import { describe, expect, it } from "vitest";
import { generateRsaJwk } from "../../../packages/core/test/keys.js";
import type { Env } from "../src/config.js";
import { call, testSigningKey, useFixture } from "./fixture.js";

describe("fail-closed configuration", () => {
  const fixture = useFixture();

  it.each<[string, (env: Env) => Env]>([
    ["no issuer", ({ ISSUER: _, ...env }) => env],
    ["an issuer with a path", (env) => ({ ...env, ISSUER: "https://idp.example.com/" })],
    ["an http issuer", (env) => ({ ...env, ISSUER: "http://idp.example.com" })],
    ["no Ed25519 key", ({ SIGNING_KEY_ED25519_CURRENT: _, ...env }) => env],
    ["a malformed key", (env) => ({ ...env, SIGNING_KEY_ED25519_CURRENT: "{" })],
    ["an RSA previous key without a current one", (env) => ({ ...env, SIGNING_KEY_RSA_PREVIOUS: env.SIGNING_KEY_ED25519_CURRENT ?? "" })],
    ["the same key in two slots", (env) => ({ ...env, SIGNING_KEY_ED25519_PREVIOUS: env.SIGNING_KEY_ED25519_CURRENT ?? "" })],
    ["no D1 binding", (env) => ({ ...env, DB: undefined as unknown as D1Database })],
    // The limiter is the only in-Worker guard on the pre-authentication D1 writes; it is never skipped.
    ["no Rate Limiting binding", ({ RATE_LIMITER: _, ...env }) => env],
    ["a Rate Limiting binding without limit()", (env) => ({ ...env, RATE_LIMITER: {} as unknown as RateLimit })],
    // The version goes into every audit row the Worker writes; without it no row could say which code wrote it.
    ["no version metadata", ({ CF_VERSION_METADATA: _, ...env }) => env],
    ["an empty version id", (env) => ({ ...env, CF_VERSION_METADATA: { id: "", tag: "", timestamp: "" } })],
  ])("refuses every request with %s", async (_name, change) => {
    const f = fixture();
    const env = change(f.env);
    for (const path of ["/.well-known/openid-configuration", "/jwks", "/authorize", "/userinfo"]) {
      const res = await call(f, "GET", path, { env });
      expect(res.status).toBe(500);
      expect(await res.text()).not.toMatch(/kty|"d"|SIGNING_KEY/);
    }
    // The refusal is remembered for the environment: the second request does not re-parse a different answer.
    expect((await call(f, "POST", "/token", { env })).status).toBe(500);
  });

  it("serves once the configuration is valid, with RS256 when an RSA key is configured", async () => {
    const f = fixture();
    const env: Env = { ...f.env, SIGNING_KEY_RSA_CURRENT: JSON.stringify(await generateRsaJwk()) };
    const res = await call(f, "GET", "/.well-known/openid-configuration", { env });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>)["id_token_signing_alg_values_supported"]).toEqual(["Ed25519", "RS256"]);
    expect(await testSigningKey()).toBe(f.env.SIGNING_KEY_ED25519_CURRENT);
  });

  it("answers only on the issuer host, never on a Host it was not configured for", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/.well-known/openid-configuration", { origin: "https://evil.example.net" });
    expect(res.status).toBe(404);
  });

  it.each([
    ["POST", "/token"],
    ["GET", "/authorize"],
    ["GET", "/userinfo"],
  ])("refuses plain http %s %s without processing it", async (method, path) => {
    const f = fixture();
    const res = await call(f, method, path, {
      origin: "http://idp.example.com",
      headers: { authorization: `Basic ${btoa("app:secret")}` },
      ...(method === "POST" ? { form: { grant_type: "authorization_code", code: "x" } } : {}),
    });
    expect(res.status).toBe(404);
    expect(res.headers.get("www-authenticate")).toBeNull();
    expect(await res.text()).toBe("Not Found");
  });
});
