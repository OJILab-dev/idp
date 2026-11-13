import { beforeAll, describe, expect, it } from "vitest";
import { IdTokenError, verifyIdToken, type IdTokenExpectation } from "../src/id-token.js";
import { CLIENT_ID, FakeIdp, ISSUER, KID, SUB, type JsonObject } from "./support/fake-idp.js";
const NOW = 1_800_000_000;
const NONCE = "nonce-1";
const EXPECTED: IdTokenExpectation = { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE, now: NOW };

let idp: FakeIdp;
let keys: readonly unknown[];

beforeAll(async () => {
  idp = await FakeIdp.create({}, () => NOW);
  const response = await idp.fetch(new Request(`${ISSUER}/jwks`));
  keys = ((await response.json()) as { keys: unknown[] }).keys;
});

async function token(claims: JsonObject = {}, header: JsonObject = {}, foreign = false): Promise<string> {
  // An undefined claim is dropped by JSON.stringify, which removes it from the signed payload.
  return idp.sign({ ...idp.idTokenClaims(NONCE), ...claims }, header, foreign);
}

async function reason(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof IdTokenError) return error.reason;
    throw error;
  }
  return "accepted";
}

describe("verifyIdToken", () => {
  it("accepts the IdP's token and returns its claims", async () => {
    const claims = await verifyIdToken(await token(), EXPECTED, keys);
    expect(claims).toMatchObject({ iss: ISSUER, sub: SUB, aud: CLIENT_ID, nonce: NONCE, exp: NOW + 300, iat: NOW, name: "Alice" });
  });

  it("accepts an aud array that holds the client_id alone", async () => {
    await expect(verifyIdToken(await token({ aud: [CLIENT_ID] }), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
  });

  it("accepts an azp that names this client (OIDC Core §3.1.3.7 5)", async () => {
    await expect(verifyIdToken(await token({ azp: CLIENT_ID }), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
  });

  it("ignores at_hash: OPTIONAL in the code flow and not validated by this RP (§3.1.3.6, §3.1.3.8)", async () => {
    await expect(verifyIdToken(await token({ at_hash: "not-checked" }), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
  });

  it("refuses an encrypted ID token (five segments, JWE): this client registered no encryption (§3.1.3.7 1)", async () => {
    expect(await reason(verifyIdToken("a.b.c.d.e", EXPECTED, keys))).toBe("format");
  });

  it("allows a small clock skew on exp and iat", async () => {
    await expect(verifyIdToken(await token({ exp: NOW - 30 }), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
    await expect(verifyIdToken(await token({ iat: NOW + 30 }), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
  });

  it.each<[string, JsonObject, string]>([
    ["another issuer", { iss: "https://evil.example" }, "iss"],
    ["an issuer with a trailing slash", { iss: `${ISSUER}/` }, "iss"],
    ["another audience", { aud: "other-client" }, "aud"],
    ["an audience array with another client", { aud: [CLIENT_ID, "other-client"] }, "aud"],
    ["an azp naming another client", { azp: "other-client" }, "aud"],
    ["another nonce", { nonce: "nonce-2" }, "nonce"],
    ["no nonce", { nonce: undefined }, "nonce"],
    ["an expired token", { exp: NOW - 120 }, "exp"],
    ["a token issued in the future", { iat: NOW + 120 }, "iat"],
    ["a token issued long ago", { iat: NOW - 3600, exp: NOW + 300 }, "iat"],
    ["no sub", { sub: undefined }, "claims"],
    ["a string exp", { exp: String(NOW + 300) }, "claims"],
  ])("refuses %s", async (_name, claims, expected) => {
    expect(await reason(verifyIdToken(await token(claims), EXPECTED, keys))).toBe(expected);
  });

  it("refuses a bad signature: a key the JWKS does not list under that kid", async () => {
    expect(await reason(verifyIdToken(await token({}, {}, true), EXPECTED, keys))).toBe("signature");
  });

  it("refuses a token whose payload was changed after signing", async () => {
    const [header, , signature] = (await token()).split(".");
    const forged = btoa(JSON.stringify({ ...idp.idTokenClaims(NONCE), sub: "someone-else" })).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
    expect(await reason(verifyIdToken(`${header}.${forged}.${signature}`, EXPECTED, keys))).toBe("signature");
  });

  it.each<[string, JsonObject, string]>([
    // RFC 9864 deprecated "EdDSA"; the IdP never issues it (tokens.md, 署名アルゴリズム).
    ["the deprecated EdDSA identifier", { alg: "EdDSA" }, "header"],
    ["alg none", { alg: "none" }, "header"],
    ["RS256 against an Ed25519 key", { alg: "RS256" }, "header"],
    ["an embedded jwk", { jwk: { kty: "OKP" } }, "header"],
    ["a jku", { jku: "https://evil.example/jwks" }, "header"],
    ["an x5u", { x5u: "https://evil.example/cert.pem" }, "header"],
    ["an x5c", { x5c: ["MIIB"] }, "header"],
    // RFC 7515 §4.1.11: a crit this RP does not understand (it understands none) makes the JWS invalid.
    ["crit", { crit: ["exp"] }, "header"],
    ["another typ", { typ: "at+jwt" }, "header"],
    ["a non-string typ", { typ: 1 }, "header"],
    ["an unknown kid", { kid: "rotated-away" }, "unknown_kid"],
    ["a non-string kid", { kid: 1 }, "header"],
  ])("refuses a header with %s", async (_name, header, expected) => {
    // An undefined member is dropped by JSON.stringify, so { kid: undefined } signs a header without kid.
    const signed = await idp.sign(idp.idTokenClaims(NONCE), header);
    expect(await reason(verifyIdToken(signed, EXPECTED, keys))).toBe(expected);
  });

  it.each(["a.b", "!!!.!!!.!!!"])("refuses the malformed token %j", async (value) => {
    expect(await reason(verifyIdToken(value, EXPECTED, keys))).not.toBe("accepted");
  });

  it.each<[string, JsonObject]>([
    // RFC 7515 §4: header parameters that are not understood MUST be ignored.
    ["an x5t", { x5t: "dGh1bWJwcmludA" }],
    ["a private member", { "https://example.com/hint": "x" }],
    // RFC 7515 §4.1.9: typ is case-insensitive, and "application/" may be omitted.
    ["typ jwt in lower case", { typ: "jwt" }],
    ["typ application/JWT", { typ: "application/JWT" }],
    ["no typ", { typ: undefined }],
  ])("accepts a header with %s", async (_name, header) => {
    await expect(verifyIdToken(await idp.sign(idp.idTokenClaims(NONCE), header), EXPECTED, keys)).resolves.toMatchObject({ sub: SUB });
  });

  // OIDC Core §10.1: kid is required only when the JWKS holds more than one usable key.
  it("accepts a token without kid when the JWKS has exactly one usable Ed25519 signing key", async () => {
    // An undefined member is dropped by JSON.stringify, so { kid: undefined } signs a header without kid.
    const signed = await idp.sign(idp.idTokenClaims(NONCE), { kid: undefined });
    const withUnusable = [...keys, { kty: "RSA", kid: "rsa", n: "AQAB", e: "AQAB" }];
    await expect(verifyIdToken(signed, EXPECTED, withUnusable)).resolves.toMatchObject({ sub: SUB });
  });

  it("refuses a token without kid when the JWKS has more than one usable key", async () => {
    const signed = await idp.sign(idp.idTokenClaims(NONCE), { kid: undefined });
    const twoKeys = [...keys, { ...(keys[0] as JsonObject), kid: "second" }];
    expect(await reason(verifyIdToken(signed, EXPECTED, twoKeys))).toBe("unknown_kid");
  });

  it("refuses a JWKS entry that is not an Ed25519 signing key, even under the right kid", async () => {
    const rsaLike = [{ kty: "RSA", kid: KID, n: "AQAB", e: "AQAB" }];
    expect(await reason(verifyIdToken(await token(), EXPECTED, rsaLike))).toBe("unknown_kid");
    const encryption = (keys as JsonObject[]).map((key) => ({ ...key, use: "enc" }));
    expect(await reason(verifyIdToken(await token(), EXPECTED, encryption))).toBe("unknown_kid");
  });
});
