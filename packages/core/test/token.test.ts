// /token against the real schema: client enablement before authentication, client_secret_basic and public clients,
// PKCE, redirect_uri, current access, the issuing session, and atomic single use of the code
// (docs/design/security-checklist.md, OIDC and passkey sections).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { base64urlDecode, sha256Base64url } from "../src/shared/index.js";
import {
  authorize,
  exchangeToken,
  logout,
  resumeAuthorize,
  verifyAccessToken,
  verifyJws,
  type OidcDeps,
  type TokenResponse,
} from "../src/user/index.js";
import {
  CONFIDENTIAL_SECRET,
  PKCE,
  createFixture,
  issuer,
  sharedEd25519Keys,
  sharedRsaKeys,
  type Fixture,
} from "./oidc-fixture.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const CREDENTIAL = "cred-alice";
const WEB = "web-app";
const OTHER_WEB = "other-app";
const CLI = "cli-app";
const WEB_REDIRECT = "https://app.example.com/callback";
const CLI_REDIRECT = "http://127.0.0.1:51004/callback";

let f: Fixture;
let session: string;

async function seed(fixture: Fixture): Promise<void> {
  await fixture.addUser(USER, { name: "Alice" });
  await fixture.addCredential(CREDENTIAL, USER);
  await fixture.addClient({ id: WEB });
  await fixture.addClient({ id: OTHER_WEB, secret: "b3RoZXItb3RoZXItb3RoZXItb3RoZXItb3RoZXItb3R" });
  await fixture.addClient({ id: CLI, type: "public", redirectUris: ["http://127.0.0.1/callback"] });
  await fixture.grant(USER, WEB);
  await fixture.grant(USER, OTHER_WEB);
  await fixture.grant(USER, CLI);
}

beforeEach(async () => {
  f = await createFixture();
  await seed(f);
  session = await f.addSession(USER, CREDENTIAL);
});

afterEach(async () => {
  await f.dispose();
});

function basic(clientId: string, secret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`;
}

/** Gets a code for the web client from an existing session (or, for the public client, through a fresh session). */
async function codeFor(
  options: { readonly clientId?: string; readonly redirectUri?: string; readonly scope?: string; readonly nonce?: string | null } = {},
): Promise<string> {
  const clientId = options.clientId ?? WEB;
  const isPublic = clientId === CLI;
  const params: [string, string][] = [
    ["client_id", clientId],
    ["redirect_uri", options.redirectUri ?? (isPublic ? CLI_REDIRECT : WEB_REDIRECT)],
    ["response_type", "code"],
    ["scope", options.scope ?? "openid profile"],
    ["code_challenge", PKCE.challenge],
    ["code_challenge_method", "S256"],
  ];
  if (options.nonce !== null) params.push(["nonce", options.nonce ?? "nonce-1"]);
  if (isPublic) {
    const started = await authorize(f.deps, { params, sessionToken: undefined, acceptLanguage: undefined });
    if (started.kind !== "sign_in") throw new Error(started.kind);
    const fresh = await f.addSession(USER, CREDENTIAL, f.clock.now());
    const resumed = await resumeAuthorize(f.deps, { authorizeRequestId: started.authorizeRequestId, sessionToken: fresh, acceptLanguage: undefined });
    if (resumed.kind !== "code_redirect") throw new Error(resumed.kind);
    return new URL(resumed.location).searchParams.get("code") ?? "";
  }
  const decision = await authorize(f.deps, { params, sessionToken: session, acceptLanguage: undefined });
  if (decision.kind !== "code_redirect") throw new Error(decision.kind);
  return new URL(decision.location).searchParams.get("code") ?? "";
}

function form(code: string, overrides: Readonly<Record<string, string | undefined>> = {}): readonly (readonly [string, string])[] {
  const base: Record<string, string | undefined> = {
    grant_type: "authorization_code",
    code,
    redirect_uri: WEB_REDIRECT,
    code_verifier: PKCE.verifier,
    ...overrides,
  };
  return Object.entries(base).flatMap(([name, value]) => (value === undefined ? [] : [[name, value] as const]));
}

function exchange(
  code: string,
  overrides: Readonly<Record<string, string | undefined>> = {},
  // null means no Authorization header; undefined would fall back to the default.
  authorization: string | null = basic(WEB, CONFIDENTIAL_SECRET),
  deps: OidcDeps = f.deps,
): Promise<TokenResponse> {
  return exchangeToken(deps, { authorization: authorization ?? undefined, params: form(code, overrides) });
}

function expectError(response: TokenResponse, error: string, status: number): void {
  expect(response.status).toBe(status);
  expect(response.body).toEqual({ error });
  expect(response.headers["Cache-Control"]).toBe("no-store");
}

async function codeCount(): Promise<number> {
  return (await f.query("SELECT code_hash FROM auth_codes")).length;
}

function payloadOf(jwt: string): Readonly<Record<string, unknown>> {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(jwt.split(".")[1] ?? ""))) as Record<string, unknown>;
}

describe("exchangeToken: success", () => {
  it("returns the ID token and access token with Cache-Control no-store, and consumes the code", async () => {
    const code = await codeFor({ scope: "openid email profile" });
    const response = await exchange(code);
    expect(response.status).toBe(200);
    expect(response.headers).toEqual({ "Cache-Control": "no-store", Pragma: "no-cache" });
    if (!("access_token" in response.body)) throw new Error("expected success");
    expect(response.body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "openid profile" });

    const idToken = await verifyJws(response.body.id_token, { keys: f.deps.keys.all, algorithms: ["Ed25519"], typ: "JWT" });
    expect(idToken.payload).toEqual({
      iss: issuer.url,
      sub: USER,
      aud: WEB,
      exp: f.clock.now() + 300,
      iat: f.clock.now(),
      auth_time: f.clock.now() - 60,
      nonce: "nonce-1",
      name: "Alice",
    });
    const access = await verifyAccessToken(response.body.access_token, { issuer, keys: f.deps.keys, now: f.clock.now() });
    expect(access).toMatchObject({ sub: USER, client_id: WEB, scope: "openid profile" });
    expect(await codeCount()).toBe(0);
  });

  it("omits nonce and name when neither was requested", async () => {
    const code = await codeFor({ scope: "openid", nonce: null });
    const response = await exchange(code);
    if (!("id_token" in response.body)) throw new Error("expected success");
    const claims = payloadOf(response.body.id_token);
    expect(claims).not.toHaveProperty("nonce");
    expect(claims).not.toHaveProperty("name");
    expect(response.body.scope).toBe("openid");
  });

  it("accepts a public client that sends only client_id", async () => {
    const code = await codeFor({ clientId: CLI });
    const response = await exchange(code, { client_id: CLI, redirect_uri: CLI_REDIRECT }, null);
    expect(response.status).toBe(200);
  });

  it("accepts client_id in the body when it equals the Basic client", async () => {
    const code = await codeFor();
    expect((await exchange(code, { client_id: WEB })).status).toBe(200);
  });

  it("signs the ID token with RS256 for an RS256 client", async () => {
    await f.dispose();
    f = await createFixture(await sharedRsaKeys());
    await seed(f);
    await f.addClient({ id: "rsa-app", alg: "RS256" });
    await f.grant(USER, "rsa-app");
    session = await f.addSession(USER, CREDENTIAL);
    const code = await codeFor({ clientId: "rsa-app" });
    const response = await exchange(code, {}, basic("rsa-app", CONFIDENTIAL_SECRET));
    if (!("id_token" in response.body)) throw new Error("expected success");
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(response.body.id_token.split(".")[0] ?? ""))) as { alg: string };
    expect(header.alg).toBe("RS256");
  });
});

describe("exchangeToken: the code is single-use (RFC 6749 §4.1.2)", () => {
  it("rejects a second exchange of the same code", async () => {
    const code = await codeFor();
    expect((await exchange(code)).status).toBe(200);
    expectError(await exchange(code), "invalid_grant", 400);
  });

  it("lets only one of two concurrent exchanges succeed", async () => {
    const code = await codeFor();
    const results = await Promise.all([exchange(code), exchange(code)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
  });
});

describe("exchangeToken: client checks come before the code is touched", () => {
  it("rejects a disabled client with invalid_client before authentication and keeps the code", async () => {
    const code = await codeFor();
    await f.setClientEnabled(WEB, false);
    expectError(await exchange(code), "invalid_client", 401);
    expectError(await exchange(code, {}, basic(WEB, "wrong")), "invalid_client", 401);
    expect(await codeCount()).toBe(1);
  });

  it.each([
    ["no client authentication", null, { client_id: WEB }],
    ["a wrong secret", basic(WEB, "d3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmctd3J"), {}],
    ["client_secret_post", null, { client_id: WEB, client_secret: CONFIDENTIAL_SECRET }],
    ["Basic plus client_secret in the body", basic(WEB, CONFIDENTIAL_SECRET), { client_secret: CONFIDENTIAL_SECRET }],
    ["an unknown client", basic("nobody", CONFIDENTIAL_SECRET), {}],
    ["a malformed client ID", basic("Not A Client", CONFIDENTIAL_SECRET), {}],
    ["a body client_id that differs from Basic", basic(WEB, CONFIDENTIAL_SECRET), { client_id: OTHER_WEB }],
    ["a non-Basic Authorization scheme", "Bearer abc", {}],
    ["malformed Basic credentials", "Basic !!!", {}],
    ["Basic without a colon", `Basic ${btoa(WEB)}`, {}],
    ["no client at all", null, {}],
  ] as const)("rejects a confidential client with %s as invalid_client and keeps the code", async (_name, authorization, overrides) => {
    const code = await codeFor();
    const response = await exchange(code, overrides, authorization);
    expectError(response, "invalid_client", 401);
    expect(response.headers["WWW-Authenticate"]).toBe(`Basic realm="${issuer.url}"`);
    expect(await codeCount()).toBe(1);
  });

  it("does not accept a secret from a public client (RFC 8252 §8.5)", async () => {
    const code = await codeFor({ clientId: CLI });
    expectError(await exchange(code, { redirect_uri: CLI_REDIRECT }, basic(CLI, "anything")), "invalid_client", 401);
    expectError(
      await exchange(code, { client_id: CLI, client_secret: "anything", redirect_uri: CLI_REDIRECT }, null),
      "invalid_client",
      401,
    );
    expectError(await exchange(code, { redirect_uri: CLI_REDIRECT }, basic(CLI, "")), "invalid_client", 401);
    expect(await codeCount()).toBe(1);
  });

  it("rejects a code issued to another client and keeps it", async () => {
    const code = await codeFor({ clientId: OTHER_WEB });
    expectError(await exchange(code), "invalid_grant", 400);
    expect(await codeCount()).toBe(1);
  });
});

describe("exchangeToken: request checks", () => {
  it.each([
    ["missing grant_type", { grant_type: undefined }, "invalid_request"],
    ["grant_type password", { grant_type: "password" }, "unsupported_grant_type"],
    ["grant_type refresh_token", { grant_type: "refresh_token" }, "unsupported_grant_type"],
    ["missing code", { code: undefined }, "invalid_request"],
    ["missing redirect_uri", { redirect_uri: undefined }, "invalid_request"],
    ["missing code_verifier", { code_verifier: undefined }, "invalid_request"],
    ["a malformed code_verifier", { code_verifier: "short" }, "invalid_request"],
  ] as const)("rejects %s as %s and keeps the code", async (_name, overrides, error) => {
    const code = await codeFor();
    expectError(await exchange(code, overrides), error, 400);
    expect(await codeCount()).toBe(1);
  });

  it("rejects a repeated parameter (RFC 6749 §3.2)", async () => {
    const code = await codeFor();
    const response = await exchangeToken(f.deps, {
      authorization: basic(WEB, CONFIDENTIAL_SECRET),
      params: [...form(code), ["code", code]],
    });
    expectError(response, "invalid_request", 400);
  });

  it.each([
    ["an unknown code", { code: "A".repeat(43) }],
    ["a malformed code", { code: "nope" }],
    ["a wrong code_verifier (PKCE)", { code_verifier: "x".repeat(43) }],
    ["a different redirect_uri", { redirect_uri: "https://app.example.com/other" }],
  ] as const)("rejects %s as invalid_grant and keeps the code", async (_name, overrides) => {
    const code = await codeFor();
    expectError(await exchange(code, overrides), "invalid_grant", 400);
    expect(await codeCount()).toBe(1);
    expect((await exchange(code)).status).toBe(200);
  });

  it("rejects an expired code", async () => {
    const code = await codeFor();
    f.clock.advance(60);
    expectError(await exchange(code), "invalid_grant", 400);
  });
});

describe("exchangeToken: the current state is checked again", () => {
  it("rejects the code after the issuing session signed out (the code goes with it)", async () => {
    const code = await codeFor();
    await logout(f.deps, session);
    expectError(await exchange(code), "invalid_grant", 400);
    expect(await codeCount()).toBe(0);
  });

  it("rejects the code when the issuing session's row is still there but has expired", async () => {
    const nearlyExpired = await f.addSession(USER, CREDENTIAL, f.clock.now() - 3590);
    session = nearlyExpired;
    const code = await codeFor();
    f.clock.advance(10);
    expectError(await exchange(code), "invalid_grant", 400);
    expect(await codeCount()).toBe(1);
  });

  it("rejects the code after the session's passkey was revoked (cascade)", async () => {
    const code = await codeFor();
    await f.run("DELETE FROM credentials WHERE id = ?", CREDENTIAL);
    expectError(await exchange(code), "invalid_grant", 400);
  });

  it("rejects the code when the grant was removed, without consuming it", async () => {
    const code = await codeFor();
    await f.run("DELETE FROM client_access WHERE principal_id = ? AND client_id = ?", USER, WEB);
    expectError(await exchange(code), "invalid_grant", 400);
    expect(await codeCount()).toBe(1);
  });

  it("rejects the code when the user was disabled (Pocket ID CVE-2026-43983)", async () => {
    const code = await codeFor();
    await f.setUserEnabled(USER, false);
    expectError(await exchange(code), "invalid_grant", 400);
  });

  it("returns server_error without consuming the code when an RS256 client has no RSA key", async () => {
    await f.dispose();
    f = await createFixture(await sharedRsaKeys());
    await seed(f);
    await f.addClient({ id: "rsa-app", alg: "RS256" });
    await f.grant(USER, "rsa-app");
    session = await f.addSession(USER, CREDENTIAL);
    const code = await codeFor({ clientId: "rsa-app" });
    const withoutRsa: OidcDeps = { ...f.deps, keys: await sharedEd25519Keys() };
    expectError(await exchange(code, {}, basic("rsa-app", CONFIDENTIAL_SECRET), withoutRsa), "server_error", 500);
    expect(await codeCount()).toBe(1);
  });
});

describe("logout", () => {
  it("deletes only the current session row", async () => {
    const other = await f.addSession(USER, CREDENTIAL);
    await logout(f.deps, session);
    const rows = await f.query("SELECT token_hash FROM sessions");
    expect(rows).toEqual([{ token_hash: await sha256Base64url(other) }]);
  });

  it("does nothing for a missing, malformed, or unknown cookie", async () => {
    await logout(f.deps, undefined);
    await logout(f.deps, "garbage");
    await logout(f.deps, "A".repeat(43));
    expect(await f.query("SELECT token_hash FROM sessions")).toHaveLength(1);
  });
});
