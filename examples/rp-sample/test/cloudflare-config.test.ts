import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { RP_SAMPLE_WORKER_NAME, workerConfig, type DeployEnv } from "../cloudflare.config.js";

const DEPLOY: DeployEnv = {
  RP_SAMPLE_ISSUER: "https://idp.team-1.workers.dev",
  RP_SAMPLE_CLIENT_ID: "rp-sample",
  RP_SAMPLE_ORIGIN: "https://rp-sample.team-1.workers.dev",
};

describe("examples/rp-sample cloudflare.config.ts", () => {
  it("serves only on workers.dev under the fixed name, with preview URLs off", () => {
    const worker = workerConfig(DEPLOY);
    expect(worker.name).toBe("rp-sample");
    expect(RP_SAMPLE_WORKER_NAME).toBe("rp-sample");
    expect(worker.workersDev).toBe(true);
    expect(worker.previewUrls).toBe(false);
    expect(worker.domains).toBeUndefined();
  });

  it("passes the issuer, client_id, and origin as plain text vars", () => {
    expect(workerConfig(DEPLOY).env).toEqual({
      ISSUER: { type: "text", value: "https://idp.team-1.workers.dev" },
      CLIENT_ID: { type: "text", value: "rp-sample" },
      ORIGIN: { type: "text", value: "https://rp-sample.team-1.workers.dev" },
    });
  });

  it("keeps the callback's code and state out of Workers Logs", () => {
    expect(workerConfig(DEPLOY).observability?.redactQueryString).toBe(true);
  });

  it("never holds a secret: CLIENT_SECRET and SESSION_KEY are Worker Secrets set by a script", () => {
    expect(JSON.stringify(workerConfig(DEPLOY))).not.toMatch(/CLIENT_SECRET|SESSION_KEY/);
  });

  it("loads under Node's own module loader, which cf uses", () => {
    const configUrl = new URL("../cloudflare.config.ts", import.meta.url).href;
    const script = `const m = await import(${JSON.stringify(configUrl)}); if (m.workerConfig(process.env).name !== "rp-sample") process.exit(1);`;
    const env = { ...process.env, ...DEPLOY };
    expect(() => execFileSync(process.execPath, ["--input-type=module", "-e", script], { env, stdio: "pipe" })).not.toThrow();
  });

  it.each<[string, DeployEnv]>([
    ["no issuer", { ...DEPLOY, RP_SAMPLE_ISSUER: undefined }],
    ["an http issuer", { ...DEPLOY, RP_SAMPLE_ISSUER: "http://idp.team-1.workers.dev" }],
    ["an issuer with a trailing slash", { ...DEPLOY, RP_SAMPLE_ISSUER: "https://idp.team-1.workers.dev/" }],
    ["no client_id", { ...DEPLOY, RP_SAMPLE_CLIENT_ID: undefined }],
    ["an invalid client_id", { ...DEPLOY, RP_SAMPLE_CLIENT_ID: "-bad" }],
    ["no origin", { ...DEPLOY, RP_SAMPLE_ORIGIN: undefined }],
    ["an origin that is not this Worker's workers.dev host", { ...DEPLOY, RP_SAMPLE_ORIGIN: "https://other.team-1.workers.dev" }],
    ["an origin with a path", { ...DEPLOY, RP_SAMPLE_ORIGIN: "https://rp-sample.team-1.workers.dev/x" }],
  ])("refuses %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
