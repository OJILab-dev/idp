// /authorize and /authorize/resume against the real schema. Each security-checklist item for the authorization
// endpoint (docs/design/security-checklist.md, OIDC and passkey sections) has at least one case here.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sha256Base64url } from "../src/shared/index.js";
import {
  authorize,
  buildIdTokenClaims,
  loadSigningKeys,
  resumeAuthorize,
  signIdToken,
  type AuthorizeDecision,
} from "../src/user/index.js";
import { generateEd25519Jwk } from "./keys.js";
import { PKCE, createFixture, issuer, sharedRsaKeys, type Fixture } from "./oidc-fixture.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_USER = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const CREDENTIAL = "cred-alice";
const OTHER_CREDENTIAL = "cred-bob";
const WEB = "web-app";
const CLI = "cli-app";
const WEB_REDIRECT = "https://app.example.com/callback";
const CLI_REDIRECT = "http://127.0.0.1/callback";

let f: Fixture;

beforeEach(async () => {
  f = await createFixture();
  await f.addUser(USER);
  await f.addCredential(CREDENTIAL, USER);
  await f.addUser(OTHER_USER, { name: "Bob" });
  await f.addCredential(OTHER_CREDENTIAL, OTHER_USER);
  await f.addClient({ id: WEB });
  await f.addClient({ id: CLI, type: "public", redirectUris: [CLI_REDIRECT] });
  await f.grant(USER, WEB);
  await f.grant(USER, CLI);
  await f.grant(OTHER_USER, WEB);
});

afterEach(async () => {
  await f.dispose();
});

type Overrides = Readonly<Record<string, string | undefined>>;

function params(overrides: Overrides = {}): readonly (readonly [string, string])[] {
  const base: Record<string, string | undefined> = {
    client_id: WEB,
    redirect_uri: WEB_REDIRECT,
    response_type: "code",
    scope: "openid profile",
    code_challenge: PKCE.challenge,
    code_challenge_method: "S256",
    state: "state-123",
    nonce: "nonce-456",
    ...overrides,
  };
  return Object.entries(base).flatMap(([name, value]) => (value === undefined ? [] : [[name, value] as const]));
}

function call(
  overrides: Overrides = {},
  options: { readonly session?: string; readonly acceptLanguage?: string; readonly extra?: readonly (readonly [string, string])[] } = {},
): Promise<AuthorizeDecision> {
  return authorize(f.deps, {
    params: [...params(overrides), ...(options.extra ?? [])],
    sessionToken: options.session,
    acceptLanguage: options.acceptLanguage,
  });
}

function redirectQuery(decision: AuthorizeDecision): URLSearchParams {
  if (decision.kind !== "error_redirect" && decision.kind !== "code_redirect") {
    throw new Error(`expected a redirect, got ${decision.kind}`);
  }
  return new URL(decision.location).searchParams;
}

function expectErrorRedirect(decision: AuthorizeDecision, error: string, base = WEB_REDIRECT): URLSearchParams {
  expect(decision.kind).toBe("error_redirect");
  if (decision.kind !== "error_redirect") throw new Error("unreachable");
  expect(decision.error).toBe(error);
  const url = new URL(decision.location);
  expect(`${url.origin}${url.pathname}`).toBe(base);
  const query = url.searchParams;
  expect(query.get("error")).toBe(error);
  expect(query.get("iss")).toBe(issuer.url);
  expect(query.has("code")).toBe(false);
  return query;
}

async function authCodeRows(): Promise<readonly Readonly<Record<string, unknown>>[]> {
  return f.query("SELECT * FROM auth_codes");
}

async function authorizeRequestRows(): Promise<readonly Readonly<Record<string, unknown>>[]> {
  return f.query("SELECT * FROM authorize_requests");
}

async function idTokenFor(sub: string, keys = f.deps.keys): Promise<string> {
  const claims = buildIdTokenClaims({
    issuer,
    sub,
    clientId: WEB,
    authTime: f.clock.now() - 600,
    nonce: undefined,
    scopes: ["openid"],
    name: "x",
    now: f.clock.now() - 600,
  });
  return signIdToken(keys, "Ed25519", claims);
}

describe("authorize: client and redirect_uri come first", () => {
  it.each([
    ["missing client_id", { client_id: undefined }, "invalid_client"],
    ["malformed client_id", { client_id: "Not A Client" }, "invalid_client"],
    ["unknown client_id", { client_id: "nobody" }, "invalid_client"],
    ["missing redirect_uri", { redirect_uri: undefined }, "invalid_redirect_uri"],
    ["unregistered redirect_uri", { redirect_uri: "https://evil.example.com/callback" }, "invalid_redirect_uri"],
    ["redirect_uri with an extra path", { redirect_uri: `${WEB_REDIRECT}/x` }, "invalid_redirect_uri"],
  ] as const)("%s gives an error page and no redirect", async (_name, overrides, error) => {
    const decision = await call(overrides);
    expect(decision).toEqual({ kind: "error_page", error, locale: "en" });
  });

  it("gives an error page even with prompt=none (Pocket ID CVE-2026-55834)", async () => {
    const decision = await call({ redirect_uri: "https://evil.example.com/callback", prompt: "none" });
    expect(decision.kind).toBe("error_page");
  });

  it("gives an error page for a disabled client even when redirect_uri matches", async () => {
    await f.setClientEnabled(WEB, false);
    expect(await call()).toEqual({ kind: "error_page", error: "invalid_client", locale: "en" });
  });

  it("gives an error page for a client with no enablement row (fail-closed)", async () => {
    await f.addClient({ id: "no-row-app", enabled: "no-row" });
    expect((await call({ client_id: "no-row-app" })).kind).toBe("error_page");
  });

  it("gives an error page when client_id or redirect_uri is repeated (RFC 6749 §3.1)", async () => {
    expect((await call({}, { extra: [["client_id", CLI]] })).kind).toBe("error_page");
    expect((await call({}, { extra: [["redirect_uri", WEB_REDIRECT]] })).kind).toBe("error_page");
  });

  it("accepts any port on a registered loopback redirect_uri (RFC 8252 §7.3)", async () => {
    const decision = await call({ client_id: CLI, redirect_uri: "http://127.0.0.1:51004/callback" });
    expect(decision.kind).toBe("sign_in");
  });

  it("does not accept localhost for a loopback registration (RFC 8252 §8.3)", async () => {
    const decision = await call({ client_id: CLI, redirect_uri: "http://localhost:51004/callback" });
    expect(decision.kind).toBe("error_page");
  });

  it("chooses the error page language from ui_locales, then Accept-Language", async () => {
    expect(await call({ client_id: "nobody", ui_locales: "ja" })).toMatchObject({ locale: "ja" });
    expect(await call({ client_id: "nobody" }, { acceptLanguage: "ja-JP,ja;q=0.9" })).toMatchObject({ locale: "ja" });
  });
});

describe("authorize: errors after validation go to the validated redirect_uri with iss and state", () => {
  it("returns a 400 page without error parameters for an unsupported response_mode", async () => {
    expect(await call({ response_mode: "fragment" })).toEqual({
      kind: "error_page",
      error: "unsupported_response_mode",
      locale: "en",
    });
  });

  it("accepts response_mode=query", async () => {
    expect((await call({ response_mode: "query" })).kind).toBe("sign_in");
  });

  it.each([
    ["request", "request_not_supported"],
    ["request_uri", "request_uri_not_supported"],
    ["registration", "registration_not_supported"],
  ] as const)("rejects %s with %s", async (name, error) => {
    const query = expectErrorRedirect(await call({ [name]: "x" }), error);
    expect(query.get("state")).toBe("state-123");
  });

  it.each([
    ["missing response_type", { response_type: undefined }, "invalid_request"],
    ["response_type token (no implicit flow)", { response_type: "token" }, "unsupported_response_type"],
    ["response_type code id_token (no hybrid flow)", { response_type: "code id_token" }, "unsupported_response_type"],
    ["scope without openid", { scope: "profile" }, "invalid_scope"],
    ["missing scope", { scope: undefined }, "invalid_scope"],
    ["missing code_challenge (PKCE downgrade, RFC 9700 §2.1.1)", { code_challenge: undefined }, "invalid_request"],
    ["code_challenge_method plain", { code_challenge_method: "plain" }, "invalid_request"],
    ["missing code_challenge_method (defaults to plain)", { code_challenge_method: undefined }, "invalid_request"],
    ["malformed code_challenge", { code_challenge: "short" }, "invalid_request"],
    ["prompt=none mixed with login", { prompt: "none login" }, "invalid_request"],
    ["unknown prompt value", { prompt: "bogus" }, "invalid_request"],
    ["negative max_age", { max_age: "-1" }, "invalid_request"],
    ["non-integer max_age", { max_age: "1.5" }, "invalid_request"],
    ["malformed id_token_hint", { id_token_hint: "not-a-jwt" }, "invalid_request"],
  ] as const)("%s gives %s", async (_name, overrides, error) => {
    const query = expectErrorRedirect(await call(overrides), error);
    expect(query.get("state")).toBe("state-123");
    expect(await authorizeRequestRows()).toEqual([]);
  });

  it("rejects a repeated parameter other than client_id and redirect_uri (RFC 6749 §3.1)", async () => {
    expectErrorRedirect(await call({}, { extra: [["scope", "openid"]] }), "invalid_request");
  });

  it("rejects an id_token_hint signed by a key the IdP does not hold", async () => {
    const outsider = await loadSigningKeys({ ed25519Current: JSON.stringify(await generateEd25519Jwk()) });
    expectErrorRedirect(await call({ id_token_hint: await idTokenFor(USER, outsider) }), "invalid_request");
  });

  it("omits state from the error response when the request had none", async () => {
    const query = expectErrorRedirect(await call({ state: undefined, scope: "profile" }), "invalid_scope");
    expect(query.has("state")).toBe(false);
  });

  it("treats an empty parameter as omitted (RFC 6749 §3.1)", async () => {
    const query = expectErrorRedirect(await call({ state: "", scope: "profile" }), "invalid_scope");
    expect(query.has("state")).toBe(false);
  });

  it("returns state byte for byte", async () => {
    const state = "a b&c=d/é";
    const query = expectErrorRedirect(await call({ state, scope: "profile" }), "invalid_scope");
    expect(query.get("state")).toBe(state);
  });

  it("keeps the registered redirect_uri's own query", async () => {
    await f.addClient({ id: "query-app", redirectUris: ["https://app.example.com/cb?tenant=a"] });
    const decision = await call({ client_id: "query-app", redirect_uri: "https://app.example.com/cb?tenant=a", scope: "x" });
    expect(redirectQuery(decision).get("tenant")).toBe("a");
  });

  it("ignores display, claims_locales, and acr_values", async () => {
    const decision = await call({ display: "popup", claims_locales: "fr", acr_values: "urn:x" });
    expect(decision.kind).toBe("sign_in");
  });

  it("returns server_error before sign-in for an RS256 client when no RSA key is configured", async () => {
    await f.addClient({ id: "rsa-app", alg: "RS256" });
    expectErrorRedirect(await call({ client_id: "rsa-app" }), "server_error");
    expect(await authorizeRequestRows()).toEqual([]);
  });
});

describe("authorize: without a usable session, the request is saved and the sign-in page shown", () => {
  it("saves the validated request under a hashed ID for 15 minutes", async () => {
    const decision = await call({ ui_locales: "ja", max_age: "120" });
    expect(decision.kind).toBe("sign_in");
    if (decision.kind !== "sign_in") return;
    expect(decision.locale).toBe("ja");
    expect(decision.expiresAt).toBe(f.clock.now() + 900);
    const rows = await authorizeRequestRows();
    expect(rows).toEqual([
      {
        id_hash: await sha256Base64url(decision.authorizeRequestId),
        client_id: WEB,
        redirect_uri: WEB_REDIRECT,
        state: "state-123",
        nonce: "nonce-456",
        code_challenge: PKCE.challenge,
        scope: "openid profile",
        prompt_login: 0,
        max_age: 120,
        id_token_hint_sub: null,
        locale: "ja",
        created_at: f.clock.now(),
        expires_at: f.clock.now() + 900,
      },
    ]);
  });

  it("returns login_required for prompt=none", async () => {
    expectErrorRedirect(await call({ prompt: "none" }), "login_required");
    expect(await authorizeRequestRows()).toEqual([]);
  });

  it("treats a malformed or unknown session cookie as no session", async () => {
    expect((await call({}, { session: "garbage" })).kind).toBe("sign_in");
    expect((await call({}, { session: "A".repeat(43) })).kind).toBe("sign_in");
  });

  it("treats an expired session as no session", async () => {
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now() - 3600);
    expect((await call({}, { session })).kind).toBe("sign_in");
  });

  it("deletes expired authorize_requests in the same batch as the new one", async () => {
    await call();
    f.clock.advance(901);
    await call();
    expect(await authorizeRequestRows()).toHaveLength(1);
  });

  it("stores the requested sign-in constraints", async () => {
    const hint = await idTokenFor(OTHER_USER);
    await call({ prompt: "login", id_token_hint: hint });
    await call({ max_age: "0" });
    await call({ prompt: "select_account" });
    const rows = await f.query("SELECT prompt_login, max_age, id_token_hint_sub FROM authorize_requests ORDER BY created_at, id_hash");
    expect(rows).toEqual(
      expect.arrayContaining([
        { prompt_login: 1, max_age: null, id_token_hint_sub: OTHER_USER },
        { prompt_login: 1, max_age: 0, id_token_hint_sub: null },
        { prompt_login: 1, max_age: null, id_token_hint_sub: null },
      ]),
    );
  });
});

describe("authorize: with a session", () => {
  it("issues a hashed, 60-second code bound to the session, client, redirect_uri, PKCE, nonce, and scope", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    const decision = await call({ scope: "openid email profile" }, { session });
    expect(decision.kind).toBe("code_redirect");
    const query = redirectQuery(decision);
    expect(query.get("state")).toBe("state-123");
    expect(query.get("iss")).toBe(issuer.url);
    const code = query.get("code") ?? "";
    expect(await authCodeRows()).toEqual([
      {
        code_hash: await sha256Base64url(code),
        client_id: WEB,
        user_id: USER,
        session_token_hash: await sha256Base64url(session),
        redirect_uri: WEB_REDIRECT,
        code_challenge: PKCE.challenge,
        nonce: "nonce-456",
        scope: "openid profile",
        auth_time: f.clock.now() - 60,
        expires_at: f.clock.now() + 60,
      },
    ]);
  });

  it("grants only openid when profile was not requested", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    await call({ scope: "openid email", nonce: undefined }, { session });
    expect(await f.query("SELECT scope, nonce FROM auth_codes")).toEqual([{ scope: "openid", nonce: null }]);
  });

  it("deletes expired codes in the same batch as a new one", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    await call({}, { session });
    f.clock.advance(61);
    await call({}, { session });
    expect(await authCodeRows()).toHaveLength(1);
  });

  it("returns access_denied when the user has no grant for the client", async () => {
    await f.addClient({ id: "other-app" });
    const session = await f.addSession(USER, CREDENTIAL);
    expectErrorRedirect(await call({ client_id: "other-app" }, { session }), "access_denied");
    expect(await authCodeRows()).toEqual([]);
  });

  it("returns access_denied for a disabled user (effective_access excludes them)", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    await f.setUserEnabled(USER, false);
    expectErrorRedirect(await call({}, { session }), "access_denied");
  });

  it("issues a code through a group grant", async () => {
    await f.addClient({ id: "group-app" });
    await f.run("INSERT INTO principals (id, kind) VALUES ('11111111-1111-4111-8111-111111111111', 'group')");
    await f.run("INSERT INTO groups (id, name, created_at) VALUES ('11111111-1111-4111-8111-111111111111', 'family', 1)");
    await f.run("INSERT INTO group_enablement_events (group_id, enablement, occurred_at) VALUES ('11111111-1111-4111-8111-111111111111', 'enabled', 1)");
    await f.run(`INSERT INTO group_members (user_id, group_id) VALUES ('${USER}', '11111111-1111-4111-8111-111111111111')`);
    await f.grant("11111111-1111-4111-8111-111111111111", "group-app");
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ client_id: "group-app" }, { session })).kind).toBe("code_redirect");
  });

  it("always re-authenticates a public client, even with a session (RFC 8252 §8.6)", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ client_id: CLI, redirect_uri: CLI_REDIRECT }, { session })).kind).toBe("sign_in");
    expectErrorRedirect(
      await call({ client_id: CLI, redirect_uri: CLI_REDIRECT, prompt: "none" }, { session }),
      "login_required",
      CLI_REDIRECT,
    );
  });

  it("re-authenticates for prompt=login and max_age=0", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ prompt: "login" }, { session })).kind).toBe("sign_in");
    expect((await call({ max_age: "0" }, { session })).kind).toBe("sign_in");
  });

  it("re-authenticates when auth_time is older than max_age, and returns login_required with prompt=none", async () => {
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now() - 301);
    expect((await call({ max_age: "300" }, { session })).kind).toBe("sign_in");
    expectErrorRedirect(await call({ max_age: "300", prompt: "none" }, { session }), "login_required");
  });

  it("issues a code when auth_time is within max_age", async () => {
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now() - 300);
    expect((await call({ max_age: "300" }, { session })).kind).toBe("code_redirect");
  });

  it("issues a code with prompt=none when the session is usable", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ prompt: "none" }, { session })).kind).toBe("code_redirect");
  });

  it("issues a code when id_token_hint names the session's user (even after the hint's exp)", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ id_token_hint: await idTokenFor(USER) }, { session })).kind).toBe("code_redirect");
  });

  it("returns login_required with prompt=none when id_token_hint names another user", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expectErrorRedirect(await call({ id_token_hint: await idTokenFor(OTHER_USER), prompt: "none" }, { session }), "login_required");
  });

  it("treats the session as absent when id_token_hint names another user", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    const decision = await call({ id_token_hint: await idTokenFor(OTHER_USER) }, { session });
    expect(decision.kind).toBe("sign_in");
    expect(await f.query("SELECT id_token_hint_sub FROM authorize_requests")).toEqual([{ id_token_hint_sub: OTHER_USER }]);
  });

  it("signs with RS256 when the key is configured", async () => {
    await f.dispose();
    f = await createFixture(await sharedRsaKeys());
    await f.addUser(USER);
    await f.addCredential(CREDENTIAL, USER);
    await f.addClient({ id: "rsa-app", alg: "RS256" });
    await f.grant(USER, "rsa-app");
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await call({ client_id: "rsa-app" }, { session })).kind).toBe("code_redirect");
  });
});

describe("resumeAuthorize", () => {
  async function startSignIn(overrides: Overrides = {}): Promise<string> {
    const decision = await call(overrides);
    if (decision.kind !== "sign_in") throw new Error(`expected sign_in, got ${decision.kind}`);
    return decision.authorizeRequestId;
  }

  function resume(authorizeRequestId: string | undefined, session: string | undefined): Promise<AuthorizeDecision> {
    return resumeAuthorize(f.deps, { authorizeRequestId, sessionToken: session, acceptLanguage: undefined });
  }

  it("issues a code for the saved request and takes the row exactly once", async () => {
    const id = await startSignIn();
    f.clock.advance(30);
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    const decision = await resume(id, session);
    expect(decision.kind).toBe("code_redirect");
    const query = redirectQuery(decision);
    expect(query.get("state")).toBe("state-123");
    expect(query.get("iss")).toBe(issuer.url);
    expect(await f.query("SELECT nonce, scope FROM auth_codes")).toEqual([{ nonce: "nonce-456", scope: "openid profile" }]);
    expect(await authorizeRequestRows()).toEqual([]);
    expect(await resume(id, session)).toEqual({ kind: "error_page", error: "invalid_authorize_request", locale: "en" });
  });

  it("gives an error page for a missing, malformed, or unknown ID", async () => {
    const session = await f.addSession(USER, CREDENTIAL);
    expect((await resume(undefined, session)).kind).toBe("error_page");
    expect((await resume("garbage", session)).kind).toBe("error_page");
    expect((await resume("A".repeat(43), session)).kind).toBe("error_page");
  });

  it("gives an error page for an expired row and still deletes it", async () => {
    const id = await startSignIn();
    f.clock.advance(900);
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    expect(await resume(id, session)).toEqual({ kind: "error_page", error: "invalid_authorize_request", locale: "en" });
    expect(await authorizeRequestRows()).toEqual([]);
  });

  it("uses the saved locale for the error page language", async () => {
    const id = await startSignIn({ ui_locales: "ja" });
    await f.setClientEnabled(WEB, false);
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    expect(await resume(id, session)).toEqual({ kind: "error_page", error: "invalid_client", locale: "ja" });
  });

  it("gives an error page when the redirect_uri is no longer registered", async () => {
    const id = await startSignIn();
    await f.run("UPDATE clients SET redirect_uris_json = ? WHERE id = ?", JSON.stringify(["https://app.example.com/new"]), WEB);
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    expect(await resume(id, session)).toMatchObject({ kind: "error_page", error: "invalid_redirect_uri" });
  });

  it("returns login_required when there is no session", async () => {
    const id = await startSignIn();
    expectErrorRedirect(await resume(id, undefined), "login_required");
  });

  it("returns access_denied when the signed-in user has no access", async () => {
    const id = await startSignIn();
    await f.run("DELETE FROM client_access WHERE principal_id = ? AND client_id = ?", OTHER_USER, WEB);
    const session = await f.addSession(OTHER_USER, OTHER_CREDENTIAL, f.clock.now());
    expectErrorRedirect(await resume(id, session), "access_denied");
    expect(await authCodeRows()).toEqual([]);
  });

  it("requires auth_time at or after the request for prompt=login", async () => {
    const id = await startSignIn({ prompt: "login" });
    const stale = await f.addSession(USER, CREDENTIAL, f.clock.now() - 1);
    expectErrorRedirect(await resume(id, stale), "login_required");
    const id2 = await startSignIn({ prompt: "login" });
    const fresh = await f.addSession(USER, CREDENTIAL, f.clock.now());
    expect((await resume(id2, fresh)).kind).toBe("code_redirect");
  });

  it("requires auth_time at or after the request for a public client", async () => {
    const id = await startSignIn({ client_id: CLI, redirect_uri: "http://127.0.0.1:51004/callback" });
    const stale = await f.addSession(USER, CREDENTIAL, f.clock.now() - 1);
    expectErrorRedirect(await resume(id, stale), "login_required", "http://127.0.0.1:51004/callback");
    const id2 = await startSignIn({ client_id: CLI, redirect_uri: "http://127.0.0.1:51004/callback" });
    const fresh = await f.addSession(USER, CREDENTIAL, f.clock.now());
    const decision = await resume(id2, fresh);
    expect(decision.kind).toBe("code_redirect");
    expect(await f.query("SELECT redirect_uri FROM auth_codes")).toEqual([{ redirect_uri: "http://127.0.0.1:51004/callback" }]);
  });

  it("checks max_age against the current time", async () => {
    const id = await startSignIn({ max_age: "60" });
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    f.clock.advance(61);
    expectErrorRedirect(await resume(id, session), "login_required");
  });

  it("returns login_required when the signed-in user differs from id_token_hint", async () => {
    const id = await startSignIn({ id_token_hint: await idTokenFor(OTHER_USER) });
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    expectErrorRedirect(await resume(id, session), "login_required");
    const id2 = await startSignIn({ id_token_hint: await idTokenFor(OTHER_USER) });
    const other = await f.addSession(OTHER_USER, OTHER_CREDENTIAL, f.clock.now());
    expect((await resume(id2, other)).kind).toBe("code_redirect");
  });

  it("cannot be resumed with another request's ID once that row is consumed", async () => {
    const id = await startSignIn();
    const session = await f.addSession(USER, CREDENTIAL, f.clock.now());
    await resume(id, session);
    expect((await resume(id, session)).kind).toBe("error_page");
  });
});
