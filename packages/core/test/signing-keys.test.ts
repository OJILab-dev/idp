import { beforeAll, describe, expect, it } from "vitest";
import { InvalidSigningKeyConfigError, loadSigningKeys, type SigningKeySecrets } from "../src/user/index.js";
import { generateEd25519Jwk, generateRsaJwk } from "./keys.js";
import { vectors } from "./vectors.js";

let ed25519A: string;
let ed25519B: string;
let rsaA: Record<string, unknown>;
let rsaB: Record<string, unknown>;

beforeAll(async () => {
  ed25519A = JSON.stringify(await generateEd25519Jwk());
  ed25519B = JSON.stringify(await generateEd25519Jwk());
  [rsaA, rsaB] = await Promise.all([generateRsaJwk(), generateRsaJwk()]);
}, 120_000);

describe("loadSigningKeys", () => {
  it.each(vectors.signing_key_jwk.valid)("loads $source", async ({ jwk, public_jwk }) => {
    const keys = await loadSigningKeys({ ed25519Current: JSON.stringify(jwk) });
    expect(keys.ed25519.kid).toBe(public_jwk["kid"]);
    expect(keys.ed25519.alg).toBe("Ed25519");
    expect(keys.ed25519.publicJwk).toEqual(public_jwk);
    expect(keys.rsa).toBeUndefined();
    expect(keys.all).toEqual([keys.ed25519]);
  });

  it("loads every slot, current before previous, Ed25519 before RSA", async () => {
    const keys = await loadSigningKeys({
      ed25519Current: ed25519A,
      ed25519Previous: ed25519B,
      rsaCurrent: JSON.stringify(rsaA),
      rsaPrevious: JSON.stringify(rsaB),
    });
    expect(keys.all.map((key) => key.alg)).toEqual(["Ed25519", "Ed25519", "RS256", "RS256"]);
    expect(keys.all[0]).toBe(keys.ed25519);
    expect(keys.all[2]).toBe(keys.rsa);
    expect(new Set(keys.all.map((key) => key.kid)).size).toBe(4);
    expect(keys.rsa?.publicJwk).toEqual({
      kty: "RSA",
      n: rsaA["n"],
      e: rsaA["e"],
      kid: keys.rsa?.kid,
      alg: "RS256",
      use: "sig",
    });
  });

  it("does not make the private keys extractable", async () => {
    const keys = await loadSigningKeys({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify(rsaA) });
    for (const key of keys.all) expect(key.privateKey.extractable).toBe(false);
  });

  it.each(vectors.signing_key_jwk.invalid_ed25519)("rejects an Ed25519 key: $reason", async ({ secret }) => {
    await expect(loadSigningKeys({ ed25519Current: secret })).rejects.toThrow(InvalidSigningKeyConfigError);
  });

  it("never puts the secret into the error", async () => {
    const leaked = '{"d":"SECRET-MATERIAL",';
    const error: unknown = await loadSigningKeys({ ed25519Current: leaked }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(InvalidSigningKeyConfigError);
    expect(String((error as Error).message)).not.toContain("SECRET-MATERIAL");
    expect((error as Error).cause).toBeUndefined();
  });

  const invalidConfigs: readonly [string, () => SigningKeySecrets][] = [
    ["no Ed25519 current", () => ({})],
    ["an empty Ed25519 current", () => ({ ed25519Current: "" })],
    ["only an Ed25519 previous", () => ({ ed25519Previous: ed25519A })],
    ["an RSA previous without an RSA current", () => ({ ed25519Current: ed25519A, rsaPrevious: JSON.stringify(rsaA) })],
    ["the same key as current and previous", () => ({ ed25519Current: ed25519A, ed25519Previous: ed25519A })],
    ["an RSA key in the Ed25519 slot", () => ({ ed25519Current: JSON.stringify(rsaA) })],
    ["an Ed25519 key in the RSA slot", () => ({ ed25519Current: ed25519A, rsaCurrent: ed25519B })],
    ["an RSA key with alg PS256", () => ({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify({ ...rsaA, alg: "PS256" }) })],
    ["an RSA key without use", () => ({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify({ ...rsaA, use: undefined }) })],
    ["an RSA public key", () => ({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify({ ...rsaA, d: undefined }) })],
    ["an RSA key without the CRT members", () => ({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify({ ...rsaA, qi: undefined }) })],
    ["an RSA key whose kid is not the thumbprint", () => ({ ed25519Current: ed25519A, rsaCurrent: JSON.stringify({ ...rsaA, kid: "rsa-1" }) })],
    ["an empty RSA current", () => ({ ed25519Current: ed25519A, rsaCurrent: "" })],
  ];

  it.each(invalidConfigs)("rejects %s", async (_name, secrets) => {
    await expect(loadSigningKeys(secrets())).rejects.toThrow(InvalidSigningKeyConfigError);
  });

  it("rejects an RSA modulus below 4096 bits", async () => {
    const rsa = JSON.stringify(await generateRsaJwk(3072));
    await expect(loadSigningKeys({ ed25519Current: ed25519A, rsaCurrent: rsa })).rejects.toThrow(
      InvalidSigningKeyConfigError,
    );
  }, 60_000);

  it("rejects an RSA modulus with a leading zero byte", async () => {
    const n = Buffer.from(String(rsaA["n"]), "base64url");
    const padded = Buffer.concat([Buffer.from([0]), n]).toString("base64url");
    const rsa = JSON.stringify({ ...rsaA, n: padded });
    await expect(loadSigningKeys({ ed25519Current: ed25519A, rsaCurrent: rsa })).rejects.toThrow(
      InvalidSigningKeyConfigError,
    );
  });
});
