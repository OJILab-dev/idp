// /userinfo: only an IdP access token (Ed25519, at+jwt, aud = issuer), with the user and access re-read from D1 on
// every call (docs/design/security-checklist.md, OIDC section).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildAccessTokenClaims,
  buildIdTokenClaims,
  loadSigningKeys,
  signAccessToken,
  signIdToken,
  userinfo,
  type GrantedScope,
  type SigningKeySet,
} from "../src/user/index.js";
import { generateEd25519Jwk } from "./keys.js";
import { createFixture, issuer, type Fixture } from "./oidc-fixture.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const WEB = "web-app";

let f: Fixture;

beforeEach(async () => {
  f = await createFixture();
  await f.addUser(USER, { name: "Alice" });
  await f.addClient({ id: WEB });
  await f.grant(USER, WEB);
});

afterEach(async () => {
  await f.dispose();
});

async function accessToken(
  options: { readonly scopes?: readonly GrantedScope[]; readonly clientId?: string; readonly keys?: SigningKeySet } = {},
): Promise<string> {
  const claims = buildAccessTokenClaims({
    issuer,
    sub: USER,
    clientId: options.clientId ?? WEB,
    scopes: options.scopes ?? ["openid", "profile"],
    now: f.clock.now(),
  });
  return signAccessToken(options.keys ?? f.deps.keys, claims);
}

function call(authorization: string | undefined): ReturnType<typeof userinfo> {
  return userinfo(f.deps, { authorization });
}

describe("userinfo", () => {
  it("returns sub and, with the profile scope, name, re-read from D1", async () => {
    const token = await accessToken();
    await f.run("UPDATE users SET name = 'Alice Renamed' WHERE id = ?", USER);
    const response = await call(`Bearer ${token}`);
    expect(response).toEqual({
      status: 200,
      headers: { "Cache-Control": "no-store", Pragma: "no-cache" },
      body: { sub: USER, name: "Alice Renamed" },
    });
  });

  it("returns only sub without the profile scope", async () => {
    const response = await call(`Bearer ${await accessToken({ scopes: ["openid"] })}`);
    expect(response.body).toEqual({ sub: USER });
  });

  it("accepts the scheme name in any case (RFC 9110 §11.1)", async () => {
    expect((await call(`bearer ${await accessToken()}`)).status).toBe(200);
  });

  it("asks for authentication without an error code when no token is sent (RFC 6750 §3.1)", async () => {
    const response = await call(undefined);
    expect(response.status).toBe(401);
    expect(response.body).toBeNull();
    expect(response.headers["WWW-Authenticate"]).toBe(`Bearer realm="${issuer.url}"`);
  });

  it.each([["Basic abc"], ["Bearer"], ["Bearer a b"]])("rejects the malformed header %j as invalid_request", async (header) => {
    const response = await call(header);
    expect(response.status).toBe(400);
    expect(response.headers["WWW-Authenticate"]).toBe(`Bearer realm="${issuer.url}", error="invalid_request"`);
  });

  async function expectInvalidToken(authorization: string): Promise<void> {
    const response = await call(authorization);
    expect(response.status).toBe(401);
    expect(response.body).toBeNull();
    expect(response.headers["WWW-Authenticate"]).toBe(`Bearer realm="${issuer.url}", error="invalid_token"`);
  }

  it("rejects an ID token", async () => {
    const claims = buildIdTokenClaims({
      issuer,
      sub: USER,
      clientId: WEB,
      authTime: f.clock.now(),
      nonce: undefined,
      scopes: ["openid"],
      name: "Alice",
      now: f.clock.now(),
    });
    await expectInvalidToken(`Bearer ${await signIdToken(f.deps.keys, "Ed25519", claims)}`);
  });

  it("rejects a token signed by a key the IdP does not hold", async () => {
    const outsider = await loadSigningKeys({ ed25519Current: JSON.stringify(await generateEd25519Jwk()) });
    await expectInvalidToken(`Bearer ${await accessToken({ keys: outsider })}`);
  });

  it("rejects an expired token (5 minutes)", async () => {
    const token = await accessToken();
    f.clock.advance(300);
    await expectInvalidToken(`Bearer ${token}`);
  });

  it("rejects a disabled user", async () => {
    const token = await accessToken();
    await f.setUserEnabled(USER, false);
    await expectInvalidToken(`Bearer ${token}`);
  });

  it("rejects a user who lost access to the token's client", async () => {
    const token = await accessToken();
    await f.run("DELETE FROM client_access WHERE principal_id = ? AND client_id = ?", USER, WEB);
    await expectInvalidToken(`Bearer ${token}`);
  });

  it("rejects a token for a disabled client", async () => {
    const token = await accessToken();
    await f.setClientEnabled(WEB, false);
    await expectInvalidToken(`Bearer ${token}`);
  });

  it("rejects a token for a client that does not exist", async () => {
    await expectInvalidToken(`Bearer ${await accessToken({ clientId: "ghost-app" })}`);
  });
});
