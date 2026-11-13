import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { workerConfig, type DeployEnv } from "../cloudflare.config.js";

const DEPLOY: DeployEnv = {
  RP_SAMPLE_ISSUER: "https://idp.team-1.workers.dev",
  RP_SAMPLE_CLIENT_ID: "rp-sample",
  RP_SAMPLE_ORIGIN: "https://rp-sample.team-1.workers.dev",
};

describe("examples/rp-sample cloudflare.config.ts", () => {
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
    ["an http issuer", { ...DEPLOY, RP_SAMPLE_ISSUER: "http://idp.team-1.workers.dev" }],
    ["an invalid client_id", { ...DEPLOY, RP_SAMPLE_CLIENT_ID: "-bad" }],
    ["an origin that is not this Worker's workers.dev host", { ...DEPLOY, RP_SAMPLE_ORIGIN: "https://other.team-1.workers.dev" }],
  ])("refuses %s", (_name, env) => {
    expect(() => workerConfig(env)).toThrow();
  });
});
