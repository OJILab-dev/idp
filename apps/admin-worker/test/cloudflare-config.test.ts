import { describe, expect, it } from "vitest";
import { ADMIN_RATE_LIMIT, adminWorkerConfig } from "../cloudflare.config.js";

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
    expect(worker.name).toBe("idp-admin");
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

  it("passes the gate's settings and bindings under the names the Worker reads", () => {
    const worker = adminWorkerConfig(DEPLOY);
    expect(worker.env).toMatchObject({
      DB: { type: "d1", id: D1_ID },
      ISSUER: { type: "text", value: "https://idp.example.com" },
      ADMIN_HOST: { type: "text", value: "admin.example.com" },
      HOSTING_MODE: { type: "text", value: "custom_domain" },
      ADMIN_SIGNING_KEYS: { type: "text", value: KEYS },
      CF_VERSION_METADATA: { type: "version-metadata" },
      // The IdP Worker's internal entrypoint, never its public fetch path (docs/design/idpctl.md).
      IDP: { type: "worker", worker: "idp", exportName: "IdpInternal" },
    });
    expect(worker.observability?.logs).toMatchObject({ enabled: true, invocationLogs: false });
  });

  it("binds its own Rate Limiting namespace from the deployment, with the provisional period and limit", () => {
    const worker = adminWorkerConfig(DEPLOY);
    expect(worker.env).toMatchObject({ RATE_LIMITER: { type: "rate-limit", namespace: "1002", simple: { limit: 10, period: 10 } } });
    // Provisional until measured (docs/design/hosting-modes.md 6.2).
    expect(ADMIN_RATE_LIMIT).toEqual({ period: 10, limit: 10 });
  });

  it.each([
    ["no hosting mode", { ...DEPLOY, IDP_HOSTING_MODE: undefined }],
    ["an unknown hosting mode", { ...DEPLOY, IDP_HOSTING_MODE: "zone" }],
    ["the workers_dev mode with custom domains", { ...DEPLOY, IDP_HOSTING_MODE: "workers_dev" }],
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
    ["a namespace with a leading zero", { ...DEPLOY, IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID: "01" }],
    ["no signing keys", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: undefined }],
    ["an empty signing-key list", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: "[]" }],
    ["signing keys that are not JSON", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: "[" }],
    ["a signing-key row with another member", { ...DEPLOY, IDP_ADMIN_SIGNING_KEYS: JSON.stringify([{ keyid: "a".repeat(64), name: "a", public_key: "x", alg: "x" }]) }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => adminWorkerConfig(env)).toThrow();
  });
});
