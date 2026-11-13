import { beforeAll, describe, expect, it } from "vitest";
import { signJwt } from "@idp/jws";
import { isRandomTokenFormat } from "../src/identifiers/index.js";
import { parseIssuer } from "../src/issuer/index.js";
import {
  InvalidTokenError,
  SigningAlgorithmUnavailableError,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  loadSigningKeys,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  verifyIdTokenHint,
  verifyLogoutIdTokenHint,
  type AccessTokenClaims,
  type IdTokenClaims,
  type SigningKeySet,
} from "../src/user/index.js";
import { generateEd25519Jwk, generateRsaJwk } from "./keys.js";
import { vectors } from "./vectors.js";

const issuer = parseIssuer("https://idp.example.com");
const otherIssuer = parseIssuer("https://other.example.com");
const sub = "0f8fad5b-d9cb-469f-a165-70867728950e";
const now = 1_793_000_100;

let keys: SigningKeySet;
let edOnly: SigningKeySet;
let outsider: SigningKeySet;

beforeAll(async () => {
  const [edCurrent, edPrevious, rsa, other] = await Promise.all([
    generateEd25519Jwk(),
    generateEd25519Jwk(),
    generateRsaJwk(),
    generateEd25519Jwk(),
  ]);
  keys = await loadSigningKeys({
    ed25519Current: JSON.stringify(edCurrent),
    ed25519Previous: JSON.stringify(edPrevious),
    rsaCurrent: JSON.stringify(rsa),
  });
  edOnly = await loadSigningKeys({ ed25519Current: JSON.stringify(edCurrent) });
  outsider = await loadSigningKeys({ ed25519Current: JSON.stringify(other) });
}, 60_000);

function accessClaims(overrides: Partial<AccessTokenClaims> = {}): AccessTokenClaims {
  return { ...buildAccessTokenClaims({ issuer, sub, clientId: "my-app", scopes: ["openid", "profile"], now }), ...overrides };
}

describe("buildIdTokenClaims", () => {
  it.each(vectors.token_claims.id_token)("builds $case", ({ input, claims }) => {
    const built = buildIdTokenClaims({
      issuer: parseIssuer(input.issuer),
      sub: input.sub,
      clientId: input.client_id,
      authTime: input.auth_time,
      nonce: input.nonce,
      scopes: input.scopes,
      name: input.name,
      now: input.now,
    });
    expect(built).toStrictEqual(claims);
    for (const forbidden of vectors.token_claims.id_token_forbidden) expect(built).not.toHaveProperty(forbidden);
  });
});

describe("buildAccessTokenClaims", () => {
  it.each(vectors.token_claims.access_token)("builds $case", ({ input, claims }) => {
    const built = buildAccessTokenClaims({
      issuer: parseIssuer(input.issuer),
      sub: input.sub,
      clientId: input.client_id,
      scopes: input.scopes,
      now: input.now,
    });
    const { jti, ...rest } = built;
    expect(rest).toStrictEqual(claims);
    expect(isRandomTokenFormat(jti)).toBe(true);
  });

  it("gives every token its own jti", () => {
    expect(accessClaims().jti).not.toBe(accessClaims().jti);
  });
});

describe("signIdToken", () => {
  function claims() {
    return buildIdTokenClaims({ issuer, sub, clientId: "my-app", authTime: now, nonce: "n", scopes: ["openid"], name: "A", now });
  }

  it.each(["Ed25519", "RS256"] as const)("signs with the current %s key", async (alg) => {
    const token = await signIdToken(keys, alg, claims());
    const header = JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8")) as unknown;
    const expectedKid = alg === "RS256" ? keys.rsa?.kid : keys.ed25519.kid;
    expect(header).toEqual({ alg, kid: expectedKid, typ: "JWT" });
  });

  it("fails closed instead of falling back when RS256 is requested without an RSA key", async () => {
    await expect(signIdToken(edOnly, "RS256", claims())).rejects.toThrow(SigningAlgorithmUnavailableError);
  });
});

describe("verifyAccessToken", () => {
  it("returns the claims of a token it issued", async () => {
    const claims = accessClaims();
    const token = await signAccessToken(keys, claims);
    expect(await verifyAccessToken(token, { issuer, keys, now: now + 299 })).toStrictEqual({
      ...claims,
      scopes: ["openid", "profile"],
    });
  });

  it("accepts a token signed with the previous Ed25519 key", async () => {
    const previous = keys.all[1];
    if (previous === undefined) throw new Error("no previous key");
    const token = await signJwt(previous, "at+jwt", accessClaims());
    await expect(verifyAccessToken(token, { issuer, keys, now })).resolves.toMatchObject({ sub });
  });

  async function rejects(token: string | Promise<string>, at = now) {
    await expect(verifyAccessToken(await token, { issuer, keys, now: at })).rejects.toThrow(InvalidTokenError);
  }

  it("rejects an RS256 access token", async () => {
    await rejects(signJwt(keys.rsa ?? keys.ed25519, "at+jwt", accessClaims()));
  });

  it("rejects an ID token", async () => {
    await rejects(signIdToken(keys, "Ed25519", buildIdTokenClaims({ issuer, sub, clientId: "my-app", authTime: now, nonce: undefined, scopes: ["openid"], name: "A", now })));
  });

  it("rejects a token signed by a key outside the set", async () => {
    await rejects(signAccessToken(outsider, accessClaims()));
  });

  it("rejects a token at and after exp", async () => {
    const token = await signAccessToken(keys, accessClaims());
    await rejects(token, now + 300);
    await rejects(token, now + 301);
  });

  it.each([
    ["another iss", { iss: otherIssuer.url }],
    ["aud set to a client", { aud: "my-app" }],
    ["an unknown scope", { scope: "openid email" }],
    ["a scope without openid", { scope: "profile" }],
    ["a duplicated scope", { scope: "openid openid" }],
    ["a non-integer exp", { exp: now + 0.5 }],
    ["a jti of the wrong form", { jti: "1" }],
    ["a sub that is not a UUIDv4", { sub: "alice" }],
  ])("rejects %s", async (_name, overrides) => {
    await rejects(signAccessToken(keys, accessClaims(overrides as Partial<AccessTokenClaims>)));
  });

  // The other claims are refused by a wrong value above, which a missing one also fails.
  it.each(["client_id", "exp", "iat"])("rejects a token without %s", async (claim) => {
    const payload = Object.fromEntries(Object.entries(accessClaims()).filter(([name]) => name !== claim));
    await rejects(signJwt(keys.ed25519, "at+jwt", payload));
  });

  it("rejects aud given as an array", async () => {
    await rejects(signJwt(keys.ed25519, "at+jwt", { ...accessClaims(), aud: [issuer.url] }));
  });
});

describe("verifyIdTokenHint", () => {
  // Overrides may break the claim types on purpose, to build hints the IdP would never issue.
  function idClaims(overrides: Record<string, unknown> = {}): IdTokenClaims {
    return {
      ...buildIdTokenClaims({ issuer, sub, clientId: "my-app", authTime: now, nonce: "n", scopes: ["openid"], name: "A", now }),
      ...overrides,
    } as IdTokenClaims;
  }

  it.each(["Ed25519", "RS256"] as const)("accepts an expired %s ID token it issued", async (alg) => {
    const token = await signIdToken(keys, alg, idClaims({ exp: now - 3600 }));
    expect(await verifyIdTokenHint(token, { issuer, keys })).toEqual({ sub });
  });

  it("rejects an RS256 hint once the RSA key is removed", async () => {
    const token = await signIdToken(keys, "RS256", idClaims());
    await expect(verifyIdTokenHint(token, { issuer, keys: edOnly })).rejects.toThrow(InvalidTokenError);
  });

  it.each([
    ["another iss", { iss: otherIssuer.url }],
    ["no sub", { sub: undefined }],
  ])("rejects %s", async (_name, overrides) => {
    const token = await signIdToken(keys, "Ed25519", idClaims(overrides));
    await expect(verifyIdTokenHint(token, { issuer, keys })).rejects.toThrow(InvalidTokenError);
  });

  it("rejects an access token", async () => {
    const token = await signAccessToken(keys, accessClaims());
    await expect(verifyIdTokenHint(token, { issuer, keys })).rejects.toThrow(InvalidTokenError);
  });

  it("rejects a token signed by a key outside the set", async () => {
    const token = await signIdToken(outsider, "Ed25519", idClaims());
    await expect(verifyIdTokenHint(token, { issuer, keys })).rejects.toThrow(InvalidTokenError);
  });
});

describe("verifyLogoutIdTokenHint", () => {
  function idClaims(overrides: Record<string, unknown> = {}): IdTokenClaims {
    return {
      ...buildIdTokenClaims({ issuer, sub, clientId: "my-app", authTime: now - 60, nonce: "n", scopes: ["openid"], name: "A", now }),
      ...overrides,
    } as IdTokenClaims;
  }

  it.each(["Ed25519", "RS256"] as const)("returns sub, aud, and auth_time of an expired %s ID token it issued", async (alg) => {
    const token = await signIdToken(keys, alg, idClaims({ exp: now - 3600 }));
    expect(await verifyLogoutIdTokenHint(token, { issuer, keys })).toEqual({ sub, aud: "my-app", authTime: now - 60 });
  });

  it("returns no auth_time for a hint without one", async () => {
    const token = await signIdToken(keys, "Ed25519", idClaims({ auth_time: undefined }));
    expect(await verifyLogoutIdTokenHint(token, { issuer, keys })).toEqual({ sub, aud: "my-app", authTime: undefined });
  });

  it.each([
    ["another iss", { iss: otherIssuer.url }],
    ["no sub", { sub: undefined }],
    ["an array aud", { aud: ["my-app"] }],
    ["an aud that is not a client ID", { aud: "Not A Client" }],
    ["a string auth_time", { auth_time: "1" }],
  ])("rejects %s", async (_name, overrides) => {
    const token = await signIdToken(keys, "Ed25519", idClaims(overrides));
    await expect(verifyLogoutIdTokenHint(token, { issuer, keys })).rejects.toThrow(InvalidTokenError);
  });

  it("rejects an access token and a token signed outside the set", async () => {
    await expect(verifyLogoutIdTokenHint(await signAccessToken(keys, accessClaims()), { issuer, keys })).rejects.toThrow(InvalidTokenError);
    await expect(verifyLogoutIdTokenHint(await signIdToken(outsider, "Ed25519", idClaims()), { issuer, keys })).rejects.toThrow(InvalidTokenError);
  });
});
