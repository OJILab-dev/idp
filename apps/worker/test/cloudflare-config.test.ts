import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { workerConfig } from "../cloudflare.config.js";

const D1_ID = "0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11";
const DEPLOY = {
  IDP_HOSTING_MODE: "custom_domain",
  IDP_ISSUER: "https://idp.example.com",
  IDP_D1_DATABASE_ID: D1_ID,
  IDP_RATE_LIMIT_NAMESPACE_ID: "1001",
  IDP_RS256_ENABLED: "false",
} as const;

describe("cloudflare.config.ts", () => {
  it("serves only on the issuer's custom domain in the custom_domain mode, with workers.dev and preview URLs off", () => {
    const worker = workerConfig(DEPLOY);
    expect(worker.domains).toEqual([{ hostname: "idp.example.com", production: true, previews: false }]);
    expect(worker.workersDev).toBe(false);
    expect(worker.previewUrls).toBe(false);
    // Every request, the pages included, runs the Worker first, so no page is served over plain http or TLS below
    // 1.2 without a zone rule (docs/design/domain-placement.md, 3; the cost is in free-tier.md).
    expect(worker.assets?.runWorkerFirst).toBe(true);
    // Workers Logs must not see the id_token_hint, state, or nonce of /authorize.
    expect(worker.observability?.redactQueryString).toBe(true);
  });

  it("serves only on workers.dev in the workers_dev mode, with no custom domain and preview URLs off", () => {
    const worker = workerConfig({ ...DEPLOY, IDP_HOSTING_MODE: "workers_dev", IDP_ISSUER: "https://idp.team-1.workers.dev" });
    expect(worker.domains).toBeUndefined();
    expect(worker.workersDev).toBe(true);
    expect(worker.previewUrls).toBe(false);
    expect(worker.env).toMatchObject({ HOSTING_MODE: { type: "text", value: "workers_dev" } });
  });

  it("binds the Rate Limiting namespace from the deployment, never a default one", () => {
    expect(workerConfig(DEPLOY).env).toMatchObject({ RATE_LIMITER: { type: "rate-limit", namespace: "1001" } });
  });

  // cf evaluates this file with Node's own loader, which strips the types but does not map a `.js` specifier to the
  // `.ts` file, so an import through the shared core's index (which re-exports `./audit.js` and so on) fails there
  // even though Vitest resolves it.
  it("loads under Node's own module loader, which cf uses", () => {
    const configUrl = new URL("../cloudflare.config.ts", import.meta.url).href;
    const script = `const m = await import(${JSON.stringify(configUrl)}); if (m.workerConfig(process.env).name !== "idp") process.exit(1);`;
    const env = { ...process.env, ...DEPLOY };
    expect(() => execFileSync(process.execPath, ["--input-type=module", "-e", script], { env, stdio: "pipe" })).not.toThrow();
  });

  it("never holds a secret: the signing keys are Worker Secrets set outside this file", () => {
    const worker = workerConfig(DEPLOY);
    expect(JSON.stringify(worker)).not.toMatch(/SIGNING_KEY/);
  });

  it.each([
    // No default mode: a missing one must not silently pick where the issuer lives (hosting-modes.md 1.1).
    ["no hosting mode", { ...DEPLOY, IDP_HOSTING_MODE: undefined }],
    // The parsers' own branches are tested in the core (hosting.test.ts, issuer.test.ts); one row each proves the wiring.
    ["the workers_dev mode with a custom-domain issuer", { ...DEPLOY, IDP_HOSTING_MODE: "workers_dev" }],
    ["no issuer", { ...DEPLOY, IDP_ISSUER: undefined }],
    ["no D1 ID", { ...DEPLOY, IDP_D1_DATABASE_ID: undefined }],
    ["a D1 name instead of an ID", { ...DEPLOY, IDP_D1_DATABASE_ID: "idp" }],
    // No default namespace: in an account shared with the service, a guess could share the service's counters.
    ["no Rate Limiting namespace", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: undefined }],
    ["a zero namespace", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: "0" }],
    ["a namespace that is not a number", { ...DEPLOY, IDP_RATE_LIMIT_NAMESPACE_ID: "idp" }],
    // No default: RS256 is offered only when the deployment file says so.
    ["no RS256 setting", { ...DEPLOY, IDP_RS256_ENABLED: undefined }],
    ["an RS256 setting that is not true or false", { ...DEPLOY, IDP_RS256_ENABLED: "1" }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
