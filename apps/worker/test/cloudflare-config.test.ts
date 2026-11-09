import { describe, expect, it } from "vitest";
import { RATE_LIMIT, workerConfig } from "../cloudflare.config.js";

const D1_ID = "0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11";
const DEPLOY = { IDP_ISSUER: "https://idp.example.com", IDP_D1_DATABASE_ID: D1_ID, IDP_RATE_LIMIT_NAMESPACE_ID: "1001" } as const;

describe("cloudflare.config.ts", () => {
  it("serves only on the issuer's custom domain, with workers.dev and preview URLs off", () => {
    const worker = workerConfig(DEPLOY);
    expect(worker.domains).toEqual([{ hostname: "idp.example.com", production: true, previews: false }]);
    expect(worker.workersDev).toBe(false);
    expect(worker.previewUrls).toBe(false);
    expect(worker.env).toMatchObject({
      DB: { type: "d1", id: D1_ID },
      ISSUER: { type: "text", value: "https://idp.example.com" },
      CF_VERSION_METADATA: { type: "version-metadata" },
    });
    // The admin Worker's IDP binding targets the internal entrypoint, not the public fetch handler.
    expect(worker.exports).toMatchObject({ IdpInternal: { type: "worker" } });
    // The pages stay pure assets: nothing is routed to the Worker before the asset lookup (free-tier.md).
    expect(worker.assets?.runWorkerFirst).toBe(false);
    // Workers Logs must not see the id_token_hint, state, or nonce of /authorize.
    expect(worker.observability?.redactQueryString).toBe(true);
  });

  it("binds the Rate Limiting namespace from the deployment, with the WAF rule's period and limit", () => {
    const worker = workerConfig(DEPLOY);
    expect(worker.env).toMatchObject({
      RATE_LIMITER: { type: "rate-limit", namespace: "1001", simple: { limit: 10, period: 10 } },
    });
    // The same provisional values as infra/main.tf's rate limiting rule (Free plan: 10-second period).
    expect(RATE_LIMIT).toEqual({ period: 10, limit: 10 });
  });

  it("never holds a secret: the signing keys are Worker Secrets set outside this file", () => {
    const worker = workerConfig(DEPLOY);
    expect(JSON.stringify(worker)).not.toMatch(/SIGNING_KEY/);
  });

  it.each([
    ["no issuer", { ...DEPLOY, IDP_ISSUER: undefined }],
    ["an issuer with a path", { ...DEPLOY, IDP_ISSUER: "https://idp.example.com/x" }],
    ["no D1 ID", { ...DEPLOY, IDP_D1_DATABASE_ID: undefined }],
    ["a D1 name instead of an ID", { ...DEPLOY, IDP_D1_DATABASE_ID: "idp" }],
    // No default namespace: in an account shared with the service, a guess could share the service's counters.
    ["no Rate Limiting namespace", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: undefined }],
    ["a zero namespace", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: "0" }],
    ["a namespace with a leading zero", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: "01" }],
    ["a namespace that is not a number", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: "idp" }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
