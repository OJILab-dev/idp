import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { workerConfig, type DeployEnv } from "../cloudflare.config.js";
import { workerConfig as idpWorkerConfig } from "../../worker/cloudflare.config.js";

const D1_ID = "0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11";
const ALLOWLIST = JSON.stringify([{ sha256: "ab".repeat(32), name: "root" }]);

const VALID: DeployEnv = {
  IDP_ISSUER: "https://idp.example.com",
  IDP_ADMIN_HOST: "admin.example.com",
  IDP_ADMIN_ALLOWLIST: ALLOWLIST,
  IDP_D1_DATABASE_ID: D1_ID,
};

describe("admin cloudflare.config.ts", () => {
  it("serves only on the admin host's custom domain, with workers.dev and preview URLs off", () => {
    const worker = workerConfig(VALID);
    expect(worker.name).toBe("idp-admin");
    expect(worker.domains).toEqual([{ hostname: "admin.example.com", production: true, previews: false }]);
    expect(worker.workersDev).toBe(false);
    expect(worker.previewUrls).toBe(false);
  });

  it("binds the shared D1, the IdP Worker, the version metadata, and the deployment's settings", () => {
    expect(workerConfig(VALID).env).toEqual({
      DB: { type: "d1", id: D1_ID },
      // The named entrypoint, never the IdP Worker's public fetch handler, which refuses a binding call.
      IDP: { type: "worker", worker: "idp", exportName: "IdpInternal" },
      ISSUER: { type: "text", value: "https://idp.example.com" },
      ADMIN_HOST: { type: "text", value: "admin.example.com" },
      ADMIN_ALLOWLIST: { type: "text", value: ALLOWLIST },
      CF_VERSION_METADATA: { type: "version-metadata" },
    });
  });

  it("binds an entrypoint the IdP Worker's own configuration exports", () => {
    const idp = idpWorkerConfig({ IDP_ISSUER: VALID.IDP_ISSUER, IDP_D1_DATABASE_ID: D1_ID, IDP_RATE_LIMIT_NAMESPACE_ID: "1001" });
    const binding = workerConfig(VALID).env?.["IDP"];
    expect(binding).toMatchObject({ type: "worker", worker: idp.name });
    expect(Object.keys(idp.exports ?? {})).toContain((binding as { exportName?: string }).exportName);
  });

  it("holds no Secret and no secret-looking value: the admin Worker binds no signing key", () => {
    const worker = workerConfig(VALID);
    expect(Object.values(worker.env ?? {}).map((b) => (b as { type: string }).type)).not.toContain("secret");
    expect(JSON.stringify(worker)).not.toMatch(/SIGNING_KEY/);
  });

  it("serves no static assets and keeps request metadata out of Workers Logs", () => {
    const worker = workerConfig(VALID);
    expect(worker.assets).toBeUndefined();
    expect(worker.observability?.redactQueryString).toBe(true);
    expect(worker.observability?.logs?.invocationLogs).toBe(false);
  });

  it("loads under Node's own module loader, which cf uses and which does not map .js specifiers to .ts", () => {
    const configUrl = new URL("../cloudflare.config.ts", import.meta.url).href;
    const script = `const m = await import(${JSON.stringify(configUrl)}); if (m.workerConfig(process.env).name !== "idp-admin") process.exit(1);`;
    expect(() => execFileSync(process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, ...VALID }, stdio: "pipe" })).not.toThrow();
  });

  it.each([
    ["no issuer", { ...VALID, IDP_ISSUER: undefined }],
    ["an issuer with a path", { ...VALID, IDP_ISSUER: "https://idp.example.com/x" }],
    ["no admin host", { ...VALID, IDP_ADMIN_HOST: undefined }],
    ["an admin host equal to the issuer host", { ...VALID, IDP_ADMIN_HOST: "idp.example.com" }],
    ["an admin host with a port", { ...VALID, IDP_ADMIN_HOST: "admin.example.com:443" }],
    ["an uppercase admin host", { ...VALID, IDP_ADMIN_HOST: "Admin.example.com" }],
    ["no allowlist", { ...VALID, IDP_ADMIN_ALLOWLIST: undefined }],
    ["an empty allowlist", { ...VALID, IDP_ADMIN_ALLOWLIST: "[]" }],
    ["an uppercase fingerprint", { ...VALID, IDP_ADMIN_ALLOWLIST: JSON.stringify([{ sha256: "AB".repeat(32), name: "root" }]) }],
    ["no D1 ID", { ...VALID, IDP_D1_DATABASE_ID: undefined }],
    ["a D1 name instead of an ID", { ...VALID, IDP_D1_DATABASE_ID: "idp" }],
  ])("refuses to build with %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
