import { describe, expect, it } from "vitest";
import { workerConfig } from "../cloudflare.config.js";

const D1_ID = "0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11";

describe("cloudflare.config.ts", () => {
  it("serves only on the issuer's custom domain, with workers.dev and preview URLs off", () => {
    const worker = workerConfig({ IDP_ISSUER: "https://idp.example.com", IDP_D1_DATABASE_ID: D1_ID });
    expect(worker.domains).toEqual([{ hostname: "idp.example.com", production: true, previews: false }]);
    expect(worker.workersDev).toBe(false);
    expect(worker.previewUrls).toBe(false);
    expect(worker.env).toMatchObject({ DB: { type: "d1", id: D1_ID }, ISSUER: { type: "text", value: "https://idp.example.com" } });
    // The pages stay pure assets: nothing is routed to the Worker before the asset lookup (free-tier.md).
    expect(worker.assets?.runWorkerFirst).toBe(false);
    // Workers Logs must not see the id_token_hint, state, or nonce of /authorize.
    expect(worker.observability?.redactQueryString).toBe(true);
  });

  it("never holds a secret: the signing keys are Worker Secrets set outside this file", () => {
    const worker = workerConfig({ IDP_ISSUER: "https://idp.example.com", IDP_D1_DATABASE_ID: D1_ID });
    expect(JSON.stringify(worker)).not.toMatch(/SIGNING_KEY/);
  });

  it.each([
    ["no issuer", { IDP_D1_DATABASE_ID: D1_ID }],
    ["an issuer with a path", { IDP_ISSUER: "https://idp.example.com/x", IDP_D1_DATABASE_ID: D1_ID }],
    ["no D1 ID", { IDP_ISSUER: "https://idp.example.com" }],
    ["a D1 name instead of an ID", { IDP_ISSUER: "https://idp.example.com", IDP_D1_DATABASE_ID: "idp" }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
