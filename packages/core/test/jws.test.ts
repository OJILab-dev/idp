import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { base64urlDecode, base64urlEncode } from "../src/shared/index.js";
import { createJwsSignature } from "../src/user/jws.js";
import { InvalidTokenError, loadSigningKeys, signJwt, verifyJws, type SigningKeySet } from "../src/user/index.js";
import { generateEd25519Jwk, generateRsaJwk } from "./keys.js";
import { vectors } from "./vectors.js";

const encoder = new TextEncoder();

function encodeJson(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(segment)));
}

let keys: SigningKeySet;
let rsaJwk: Record<string, unknown>;

beforeAll(async () => {
  rsaJwk = await generateRsaJwk();
  keys = await loadSigningKeys({
    ed25519Current: JSON.stringify(await generateEd25519Jwk()),
    ed25519Previous: JSON.stringify(await generateEd25519Jwk()),
    rsaCurrent: JSON.stringify(rsaJwk),
  });
}, 60_000);

// Signs an arbitrary header and payload with one of the loaded keys, to build tokens the IdP would never issue.
async function forge(header: unknown, payload: unknown, keyIndex = 0): Promise<string> {
  const key = keys.all[keyIndex];
  if (key === undefined) throw new Error("no such key");
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  return `${signingInput}.${await createJwsSignature(key, signingInput)}`;
}

describe("createJwsSignature", () => {
  it.each(vectors.jws_ed25519)("matches $source", async ({ jwk, signing_input, signature }) => {
    const loaded = await loadSigningKeys({ ed25519Current: JSON.stringify({ ...jwk, use: "sig", alg: "Ed25519" }) });
    expect(await createJwsSignature(loaded.ed25519, signing_input)).toBe(signature);
  });
});

describe("signJwt", () => {
  it.each([
    ["Ed25519", 0, "JWT"],
    ["RS256", 2, "JWT"],
    ["Ed25519", 0, "at+jwt"],
  ] as const)("signs with %s and typ %s in a form node:crypto verifies", async (alg, index, typ) => {
    const key = keys.all[index];
    if (key === undefined) throw new Error("no such key");
    const token = await signJwt(key, typ, { sub: "s" });
    const [header, payload, signature] = token.split(".") as [string, string, string];
    expect(decodeJson(header)).toEqual({ alg, kid: key.kid, typ });
    expect(decodeJson(payload)).toEqual({ sub: "s" });
    // An independent implementation (OpenSSL through node:crypto) must accept the signature.
    const publicKey = createPublicKey({ key: key.publicJwk as JsonWebKey, format: "jwk" });
    const data = Buffer.from(`${header}.${payload}`);
    const ok = nodeVerify(alg === "RS256" ? "sha256" : null, data, publicKey, base64urlDecode(signature));
    expect(ok).toBe(true);
  });
});

describe("verifyJws", () => {
  const both = { algorithms: ["Ed25519", "RS256"], typ: "JWT" } as const;

  it("returns the header and payload of a valid token", async () => {
    const key = keys.all[1];
    if (key === undefined) throw new Error("no such key");
    const token = await signJwt(key, "JWT", { sub: "s" });
    expect(await verifyJws(token, { ...both, keys: keys.all })).toEqual({
      header: { alg: "Ed25519", kid: key.kid, typ: "JWT" },
      payload: { sub: "s" },
    });
  });

  it("accepts RS256 when allowed", async () => {
    const token = await signJwt(keys.rsa ?? keys.ed25519, "JWT", { sub: "s" });
    await expect(verifyJws(token, { ...both, keys: keys.all })).resolves.toMatchObject({ payload: { sub: "s" } });
  });

  async function rejects(token: string | Promise<string>, options: Partial<Parameters<typeof verifyJws>[1]> = {}) {
    await expect(verifyJws(await token, { ...both, keys: keys.all, ...options })).rejects.toThrow(InvalidTokenError);
  }

  it("rejects RS256 when only Ed25519 is allowed", async () => {
    await rejects(signJwt(keys.rsa ?? keys.ed25519, "JWT", {}), { algorithms: ["Ed25519"] });
  });

  it("rejects alg none", async () => {
    await rejects(`${encodeJson({ alg: "none", kid: keys.ed25519.kid, typ: "JWT" })}.${encodeJson({})}.`);
  });

  it("rejects alg EdDSA even with a valid Ed25519 signature", async () => {
    await rejects(forge({ alg: "EdDSA", kid: keys.ed25519.kid, typ: "JWT" }, {}));
  });

  it.each(["HS256", "ed25519"])("rejects alg %s", async (alg) => {
    await rejects(forge({ alg, kid: keys.ed25519.kid, typ: "JWT" }, {}));
  });

  it("rejects RS256 in the header with an Ed25519 kid (alg bound to the key type)", async () => {
    await rejects(forge({ alg: "RS256", kid: keys.ed25519.kid, typ: "JWT" }, {}, 2));
  });

  it("rejects Ed25519 in the header with an RSA kid", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys.rsa?.kid, typ: "JWT" }, {}, 0));
  });

  it("rejects a kid not in the key set", async () => {
    const other = await loadSigningKeys({ ed25519Current: JSON.stringify(await generateEd25519Jwk()) });
    await rejects(signJwt(other.ed25519, "JWT", {}));
  });

  it.each([
    ["at+jwt", "JWT"],
    ["JWT", "at+jwt"],
  ] as const)("rejects typ %s where %s is expected", async (actual, expected) => {
    await rejects(signJwt(keys.ed25519, actual, {}), { typ: expected });
  });

  it.each(["jwt", "application/at+jwt"])("rejects typ %s for an access token", async (typ) => {
    await rejects(forge({ alg: "Ed25519", kid: keys.ed25519.kid, typ }, {}), { typ: "at+jwt" });
  });

  it.each([
    ["crit", { crit: ["exp"] }],
    ["jwk", { jwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" } }],
  ])("rejects a header with %s", async (_name, extra) => {
    await rejects(forge({ alg: "Ed25519", kid: keys.ed25519.kid, typ: "JWT", ...extra }, {}));
  });

  it("rejects a tampered payload", async () => {
    const [header, , signature] = (await signJwt(keys.ed25519, "JWT", { sub: "a" })).split(".");
    await rejects(`${header}.${encodeJson({ sub: "b" })}.${signature}`);
  });

  it("rejects a signature by another key with the same kid", async () => {
    const other = await loadSigningKeys({ ed25519Current: JSON.stringify(await generateEd25519Jwk()) });
    const signingInput = `${encodeJson({ alg: "Ed25519", kid: keys.ed25519.kid, typ: "JWT" })}.${encodeJson({})}`;
    await rejects(`${signingInput}.${await createJwsSignature(other.ed25519, signingInput)}`);
  });

  it.each([
    ["two segments", "a.b"],
    ["padding in a segment", "eyJhbGciOiJFZDI1NTE5In0=.e30.AA"],
    ["a header that is not JSON", `${base64urlEncode(encoder.encode("{"))}.e30.AA`],
    ["a header that is an array", `${encodeJson([])}.e30.AA`],
  ])("rejects %s", async (_name, token) => {
    await rejects(token);
  });

  it("rejects a payload that is not an object", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys.ed25519.kid, typ: "JWT" }, ["sub"]));
  });

  it("rejects an oversized token before parsing it", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys.ed25519.kid, typ: "JWT" }, { pad: "x".repeat(20_000) }));
  });
});
