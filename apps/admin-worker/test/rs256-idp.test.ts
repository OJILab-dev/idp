// rs256Enabled against the real IdP Worker entrypoint, not a stub: the admin Worker's IDP binding targets
// IdpInternal, and a regression in either side (the binding going through the public fetch path, which refuses calls
// without request.cf or a client IP, or the entrypoint answering differently from discovery) turns RS256 off for good.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTestD1, type TestD1 } from "../../../contract/test/d1.js";
import { generateEd25519Jwk, generateRsaJwk } from "../../../packages/core/test/keys.js";
import { parseIssuer } from "@idp/core/issuer";
import { IdpInternal } from "../../worker/src/index.js";
import type { Env as IdpEnv } from "../../worker/src/config.js";
import { rs256Enabled } from "../src/rs256.js";
import { ISSUER } from "./fixture.js";

const issuer = parseIssuer(ISSUER);

let rsaJwk: Promise<string> | undefined;

/** One RSA key per file: the contract fixes the modulus at 4096 bits, which is slow to generate. */
function rsaKey(): Promise<string> {
  rsaJwk ??= generateRsaJwk().then((jwk) => JSON.stringify(jwk));
  return rsaJwk;
}

describe("rs256Enabled over the IdP Worker's IdpInternal entrypoint", () => {
  let d1: TestD1;
  let ed25519: string;

  beforeEach(async () => {
    d1 = await createTestD1();
    ed25519 = JSON.stringify(await generateEd25519Jwk());
  });
  afterEach(async () => {
    await d1.dispose();
  });

  function idpEnv(extra: Partial<IdpEnv> = {}): IdpEnv {
    return {
      DB: d1.db,
      ISSUER,
      HOSTING_MODE: "custom_domain",
      SIGNING_KEY_ED25519_CURRENT: ed25519,
      CF_VERSION_METADATA: { id: "00000000-0000-4000-8000-0000000000bb", tag: "", timestamp: "" },
      RATE_LIMITER: { limit: async () => ({ success: true }) },
      // Part of the IdP Worker's validated environment; the entrypoint never serves a page through it.
      ASSETS: { fetch: async () => new Response(null, { status: 404 }), connect: () => { throw new Error("unused"); } } as unknown as Fetcher,
      ...extra,
    };
  }

  function entrypoint(env: IdpEnv): IdpInternal {
    return new IdpInternal({} as ExecutionContext, env);
  }

  it("reports RS256 enabled when the IdP Worker has an RSA key", async () => {
    const reasons: string[] = [];
    const env = idpEnv({ SIGNING_KEY_RSA_CURRENT: await rsaKey() });
    expect(await rs256Enabled(entrypoint(env), issuer, (reason) => reasons.push(reason))).toBe(true);
    expect(reasons).toEqual([]);
  });

  it("reports RS256 disabled when the IdP Worker has no RSA key", async () => {
    const reasons: string[] = [];
    expect(await rs256Enabled(entrypoint(idpEnv()), issuer, (reason) => reasons.push(reason))).toBe(false);
    // Disabled because discovery does not list it, not because the call failed.
    expect(reasons).toEqual([]);
  });

  it("needs neither request.cf nor a client IP: the entrypoint is not the public fetch path", async () => {
    const env = idpEnv({ SIGNING_KEY_RSA_CURRENT: await rsaKey() });
    const limited: string[] = [];
    const counting = { ...env, RATE_LIMITER: { limit: async ({ key }: RateLimitOptions) => (limited.push(key), { success: false }) } };
    expect(await rs256Enabled(entrypoint(counting), issuer, () => undefined)).toBe(true);
    expect(limited).toEqual([]);
  });

  it("treats a misconfigured IdP Worker as RS256 disabled (fail-closed)", async () => {
    const reasons: string[] = [];
    // A malformed Ed25519 key makes the IdP Worker's configuration invalid, so discovery() throws.
    const env = idpEnv({ SIGNING_KEY_ED25519_CURRENT: "{", SIGNING_KEY_RSA_CURRENT: await rsaKey() });
    expect(await rs256Enabled(entrypoint(env), issuer, (reason) => reasons.push(reason))).toBe(false);
    expect(reasons[0]).toMatch(/^discovery failed/);
  });
});
