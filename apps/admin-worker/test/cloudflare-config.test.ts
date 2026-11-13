import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { adminWorkerConfig } from "../cloudflare.config.js";
import { workerConfig as idpWorkerConfig } from "../../worker/cloudflare.config.js";

const D1_ID = "0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11";
// A public, published P-384 key (RFC 6979 Appendix A.2.6) and a keyid of the right form; the build only checks the
// shape of the rows, and the Worker checks the keys themselves at start.
const KEYS = JSON.stringify([{ keyid: "a".repeat(64), name: "alice", public_key: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE" + "A".repeat(128) }]);
const DEPLOY = {
  IDP_HOSTING_MODE: "custom_domain",
  IDP_ISSUER: "https://idp.example.com",
  IDP_ADMIN_HOST: "admin.example.com",
  IDP_D1_DATABASE_ID: D1_ID,
  IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID: "1002",
  IDP_ADMIN_SIGNING_KEYS: KEYS,
} as const;

describe("the admin Worker's cloudflare.config.ts", () => {
  it("serves only on the admin host's custom domain in the custom_domain mode, with preview URLs off", () => {
    const worker = adminWorkerConfig(DEPLOY);
    expect(worker.domains).toEqual([{ hostname: "admin.example.com", production: true, previews: false }]);
    expect(worker.workersDev).toBe(false);
    expect(worker.previewUrls).toBe(false);
  });

  it("serves only on workers.dev in the workers_dev mode", () => {
    const worker = adminWorkerConfig({
      ...DEPLOY,
      IDP_HOSTING_MODE: "workers_dev",
      IDP_ISSUER: "https://idp.team.workers.dev",
      IDP_ADMIN_HOST: "idp-admin.team.workers.dev",
    });
    expect(worker.domains).toBeUndefined();
    expect(worker.workersDev).toBe(true);
    expect(worker.previewUrls).toBe(false);
    expect(worker.env).toMatchObject({ HOSTING_MODE: { type: "text", value: "workers_dev" } });
  });

  // The deploy script deploys the IdP Worker first, so the binding's target must be an entrypoint that the IdP
  // Worker's own configuration exports; a renamed export would otherwise only fail at `cf deploy`.
  it("binds an entrypoint that the IdP Worker's configuration exports", () => {
    const idp = idpWorkerConfig({
      IDP_HOSTING_MODE: DEPLOY.IDP_HOSTING_MODE,
      IDP_ISSUER: DEPLOY.IDP_ISSUER,
      IDP_D1_DATABASE_ID: D1_ID,
      IDP_RATE_LIMIT_NAMESPACE_ID: "1001",
    });
    const binding = adminWorkerConfig(DEPLOY).env?.["IDP"];
    expect(binding).toMatchObject({ type: "worker", worker: idp.name, exportName: "IdpInternal" });
    expect(Object.keys(idp.exports ?? {})).toContain("IdpInternal");
  });

  // cf evaluates this file with Node's own loader, which does not map a `.js` specifier to the `.ts` file.
  it("loads under Node's own module loader, which cf uses", () => {
    const configUrl = new URL("../cloudflare.config.ts", import.meta.url).href;
    const script = `const m = await import(${JSON.stringify(configUrl)}); if (m.adminWorkerConfig(process.env).name !== "idp-admin") process.exit(1);`;
    const env = { ...process.env, ...DEPLOY };
    expect(() => execFileSync(process.execPath, ["--input-type=module", "-e", script], { env, stdio: "pipe" })).not.toThrow();
  });

  it("binds its own Rate Limiting namespace from the deployment, never a default one", () => {
    expect(adminWorkerConfig(DEPLOY).env).toMatchObject({ RATE_LIMITER: { type: "rate-limit", namespace: "1002" } });
  });

  it.each([
    // The parsers' own branches are tested in the core (hosting.test.ts, issuer.test.ts); these rows prove the wiring.
    ["no hosting mode", { ...DEPLOY, IDP_HOSTING_MODE: undefined }],
    ["the custom_domain mode with a workers.dev admin host", { ...DEPLOY, IDP_ADMIN_HOST: "idp-admin.team.workers.dev" }],
    ["no issuer", { ...DEPLOY, IDP_ISSUER: undefined }],
    ["no admin host", { ...DEPLOY, IDP_ADMIN_HOST: undefined }],
    ["an admin host with a port", { ...DEPLOY, IDP_ADMIN_HOST: "admin.example.com:443" }],
    ["an admin host equal to the issuer host", { ...DEPLOY, IDP_ADMIN_HOST: "idp.example.com" }],
    ["no D1 ID", { ...DEPLOY, IDP_D1_DATABASE_ID: undefined }],
    ["a D1 name instead of an ID", { ...DEPLOY, IDP_D1_DATABASE_ID: "idp" }],
    // No default namespace: a guess could share the counters of the IdP Worker or of the service's Workers.
    ["no Rate Limiting namespace", { ...DEPLOY, IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID: undefined }],
    ["a zero namespace", { ...DEPLOY, IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID: "0" }],
    ["no signing keys", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: undefined }],
    ["an empty signing-key list", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: "[]" }],
    ["signing keys that are not JSON", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: "[" }],
    ["a signing-key row with another member", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: JSON.stringify([{ keyid: "a".repeat(64), name: "a", public_key: "x", alg: "x" }]) }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => adminWorkerConfig(env)).toThrow();
  });
});
