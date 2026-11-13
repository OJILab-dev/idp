import { describe, expect, it } from "vitest";
import { generateRsaJwk } from "./domain/keys.js";
import type { Env } from "../src/config.js";
import { call, useFixture } from "./fixture.js";

describe("fail-closed configuration", () => {
  const fixture = useFixture();

  it.each<[string, (env: Env) => Env]>([
    // The issuer and hosting parsers' own branches are tested in the core; one row each proves the wiring.
    ["no issuer", ({ ISSUER: _, ...env }) => env],
    // The mode only detects a configuration that mixes the modes (docs/design/hosting-modes.md 1.4).
    ["no hosting mode", ({ HOSTING_MODE: _, ...env }) => env],
    ["the workers_dev mode with a custom-domain issuer", (env) => ({ ...env, HOSTING_MODE: "workers_dev" })],
    ["no Ed25519 key", ({ SIGNING_KEY_ED25519_CURRENT: _, ...env }) => env],
    ["a malformed key", (env) => ({ ...env, SIGNING_KEY_ED25519_CURRENT: "{" })],
    ["an RSA previous key without a current one", (env) => ({ ...env, RS256_ENABLED: "true", SIGNING_KEY_RSA_PREVIOUS: env.SIGNING_KEY_ED25519_CURRENT ?? "" })],
    // RS256 enabled must have a key to sign with, or RS256 clients would be registered that can never get a token.
    ["RS256 enabled without an RSA key", (env) => ({ ...env, RS256_ENABLED: "true" })],
    ["an RS256 setting that is not true or false", (env) => ({ ...env, RS256_ENABLED: "yes" })],
    ["the same key in two slots", (env) => ({ ...env, SIGNING_KEY_ED25519_PREVIOUS: env.SIGNING_KEY_ED25519_CURRENT ?? "" })],
    ["no D1 binding", (env) => ({ ...env, DB: undefined as unknown as D1Database })],
    // The limiter is the only in-Worker guard on the pre-authentication D1 writes; it is never skipped.
    ["no Rate Limiting binding", ({ RATE_LIMITER: _, ...env }) => env],
    ["a Rate Limiting binding without limit()", (env) => ({ ...env, RATE_LIMITER: {} as unknown as RateLimit })],
    // The pages are served through the Worker; without the binding there is nothing to serve them with.
    ["no assets binding", ({ ASSETS: _, ...env }) => env],
    ["an assets binding without fetch()", (env) => ({ ...env, ASSETS: {} as unknown as Fetcher })],
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

  // The deployment setting decides, not the presence of the Secret: an RSA key left behind is not advertised.
  it.each([
    ["true", ["Ed25519", "RS256"]],
    ["false", ["Ed25519"]],
  ])("serves with RS256_ENABLED %s and an RSA key, advertising %j", async (setting, algs) => {
    const f = fixture();
    const env: Env = { ...f.env, RS256_ENABLED: setting, SIGNING_KEY_RSA_CURRENT: JSON.stringify(await generateRsaJwk()) };
    const res = await call(f, "GET", "/.well-known/openid-configuration", { env });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>)["id_token_signing_alg_values_supported"]).toEqual(algs);
  });

  it("serves a workers.dev issuer in the workers_dev mode with the same code", async () => {
    const f = fixture();
    const issuer = "https://idp.team-1.workers.dev";
    const env: Env = { ...f.env, HOSTING_MODE: "workers_dev", ISSUER: issuer };
    const res = await call(f, "GET", "/.well-known/openid-configuration", { env, origin: issuer });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>)["issuer"]).toBe(issuer);
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
