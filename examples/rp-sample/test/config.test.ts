import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, type Env } from "../src/config.js";
import { CLIENT_ID, CLIENT_SECRET, ENV, ISSUER, ORIGIN } from "./support/fake-idp.js";

describe("loadConfig", () => {
  it("reads the plain vars and the two secrets", async () => {
    const config = await loadConfig(ENV);
    expect(config).toMatchObject({ issuer: ISSUER, clientId: CLIENT_ID, origin: ORIGIN, clientSecret: CLIENT_SECRET });
    expect(config.redirectUri).toBe(`${ORIGIN}/callback`);
    expect(config.sessionKey.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(config.sessionKey.extractable).toBe(false);
  });

  it.each<[string, Partial<Env>]>([
    ["no ISSUER", { ISSUER: undefined }],
    ["an http ISSUER", { ISSUER: "http://idp.team-1.workers.dev" }],
    ["an ISSUER with a trailing slash", { ISSUER: `${ISSUER}/` }],
    ["an invalid CLIENT_ID", { CLIENT_ID: "RP Sample" }],
    ["an ORIGIN with a path", { ORIGIN: `${ORIGIN}/app` }],
    ["an empty CLIENT_SECRET", { CLIENT_SECRET: "" }],
    ["a short SESSION_KEY", { SESSION_KEY: btoa("short") }],
  ])("fails closed with %s", async (_name, change) => {
    await expect(loadConfig({ ...ENV, ...change })).rejects.toBeInstanceOf(ConfigError);
  });

  it("never names a secret's value in its error", async () => {
    const error = await loadConfig({ ...ENV, SESSION_KEY: "not-a-key-but-secret-looking" }).catch((e: unknown) => e);
    expect(String(error)).not.toContain("not-a-key-but-secret-looking");
  });
});
