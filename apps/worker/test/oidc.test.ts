import { describe, expect, it } from "vitest";
import {
  CLIENT,
  CONFIDENTIAL_SECRET,
  CREDENTIAL,
  ISSUER,
  PKCE,
  REDIRECT_URI,
  USER,
  authorizeQuery,
  call,
  cookieValue,
  locationParams,
  seedAccess,
  setCookies,
  useFixture,
  type Fixture,
} from "./fixture.js";

const SESSION = "__Host-session";
const AUTHORIZE_REQUEST = "__Host-authorize_request";
const SAME_ORIGIN = { "sec-fetch-site": "same-origin" } as const;

function basic(id: string, secret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;
}

async function authorizeWithSession(f: Fixture, overrides: Readonly<Record<string, string | undefined>> = {}): Promise<Response> {
  const session = await f.core.addSession(USER, CREDENTIAL);
  return call(f, "GET", `/authorize?${authorizeQuery(overrides, PKCE.challenge)}`, { cookies: { [SESSION]: session } });
}

async function exchange(f: Fixture, code: string): Promise<Response> {
  return call(f, "POST", "/token", {
    headers: { authorization: basic(CLIENT, CONFIDENTIAL_SECRET) },
    form: { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE.verifier },
  });
}

describe("discovery and JWKS", () => {
  const fixture = useFixture();

  it("publishes the metadata derived from the issuer", async () => {
    const res = await call(fixture(), "GET", "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await res.json()).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      jwks_uri: `${ISSUER}/jwks`,
      id_token_signing_alg_values_supported: ["Ed25519"],
      request_uri_parameter_supported: false,
    });
  });

  it("publishes only the public members of the configured keys", async () => {
    const res = await call(fixture(), "GET", "/jwks");
    expect(res.status).toBe(200);
    const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
    expect(keys).toHaveLength(1);
    expect(Object.keys(keys[0] ?? {}).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
  });
});

describe("/authorize", () => {
  const fixture = useFixture();

  it("renders an error page, without redirecting, for an unknown client in the requested language", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "GET", `/authorize?${authorizeQuery({ client_id: "nobody", ui_locales: "fr ja" }, PKCE.challenge)}`);
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    const html = await res.text();
    expect(html).toContain('<html lang="ja">');
    expect(html).toContain("invalid_client");
    expect(html).not.toMatch(/<script|style=/);
  });

  it("renders an error page for a disabled client even when the redirect URI matches", async () => {
    const f = fixture();
    await seedAccess(f, { enabled: false });
    const res = await call(f, "GET", `/authorize?${authorizeQuery({}, PKCE.challenge)}`, { headers: { "accept-language": "en" } });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('<html lang="en">');
  });

  it("redirects errors after validation to the redirect URI with error, state, and iss", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "GET", `/authorize?${authorizeQuery({ scope: "profile" }, PKCE.challenge)}`);
    expect(res.status).toBe(302);
    const params = locationParams(res);
    expect(Object.fromEntries(params)).toEqual({ error: "invalid_scope", state: "st-1", iss: ISSUER });
  });

  it("saves the request in a __Host- cookie and sends the browser to the sign-in page", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "GET", `/authorize?${authorizeQuery({ ui_locales: "ja" }, PKCE.challenge)}`);
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/signin?lang=ja");
    const cookie = setCookies(res).get(AUTHORIZE_REQUEST);
    expect(cookie).toMatch(/; Max-Age=900(;|$)/);
    expect(cookie).toMatch(/; Path=\/(;|$)/);
    expect(cookie).toMatch(/; Secure(;|$)/);
    expect(cookie).toMatch(/; HttpOnly(;|$)/);
    expect(cookie).toMatch(/; SameSite=Lax(;|$)/);
    expect(cookie).not.toMatch(/Domain=/i);
    expect(await f.core.query("SELECT locale FROM authorize_requests")).toEqual([{ locale: "ja" }]);
  });

  it("issues a code on an existing session, with state and iss", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await authorizeWithSession(f);
    expect(res.status).toBe(302);
    const params = locationParams(res);
    expect(params.get("state")).toBe("st-1");
    expect(params.get("iss")).toBe(ISSUER);
    expect(params.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("accepts POST with a form body and answers with 303", async () => {
    const f = fixture();
    await seedAccess(f);
    const session = await f.core.addSession(USER, CREDENTIAL);
    const res = await call(f, "POST", "/authorize", {
      cookies: { [SESSION]: session },
      form: Object.fromEntries(new URLSearchParams(authorizeQuery({}, PKCE.challenge))),
    });
    expect(res.status).toBe(303);
    expect(locationParams(res).get("code")).not.toBeNull();
  });

  it("does not read the parameters of a POST from its query", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "POST", `/authorize?${authorizeQuery({}, PKCE.challenge)}`, { form: {} });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("/authorize/resume", () => {
  const fixture = useFixture();

  async function startSignIn(f: Fixture, overrides: Readonly<Record<string, string | undefined>> = {}): Promise<string> {
    const res = await call(f, "GET", `/authorize?${authorizeQuery(overrides, PKCE.challenge)}`);
    expect(res.status).toBe(303);
    return cookieValue(setCookies(res).get(AUTHORIZE_REQUEST));
  }

  it("issues the code after the passkey sign-in and clears the authorize request cookie", async () => {
    const f = fixture();
    await seedAccess(f);
    const requestId = await startSignIn(f, { prompt: "login" });
    f.core.clock.advance(30);
    // What /webauthn/auth/verify leaves behind: a fresh session for the browser.
    const session = await f.core.addSession(USER, CREDENTIAL, f.core.clock.now());
    const res = await call(f, "POST", "/authorize/resume", {
      headers: SAME_ORIGIN,
      cookies: { [AUTHORIZE_REQUEST]: requestId, [SESSION]: session },
    });
    expect(res.status).toBe(303);
    expect(locationParams(res).get("code")).not.toBeNull();
    expect(setCookies(res).get(AUTHORIZE_REQUEST)).toMatch(/Max-Age=0/);
    expect(await f.core.query("SELECT * FROM authorize_requests")).toEqual([]);
  });

  it("accepts an Origin equal to the issuer when Sec-Fetch-Site is absent", async () => {
    const f = fixture();
    await seedAccess(f);
    const requestId = await startSignIn(f);
    const session = await f.core.addSession(USER, CREDENTIAL, f.core.clock.now());
    const res = await call(f, "POST", "/authorize/resume", {
      headers: { origin: ISSUER },
      cookies: { [AUTHORIZE_REQUEST]: requestId, [SESSION]: session },
    });
    expect(res.status).toBe(303);
  });

  it.each([
    ["a cross-site request", { "sec-fetch-site": "cross-site", origin: ISSUER }],
    ["a same-site request from a sibling host", { "sec-fetch-site": "same-site" }],
    ["a foreign Origin", { origin: "https://evil.example.net" }],
    ["neither header", {}],
  ])("refuses %s without consuming the saved request", async (_name, headers) => {
    const f = fixture();
    await seedAccess(f);
    const requestId = await startSignIn(f);
    const res = await call(f, "POST", "/authorize/resume", { headers, cookies: { [AUTHORIZE_REQUEST]: requestId } });
    expect(res.status).toBe(403);
    expect(res.headers.get("location")).toBeNull();
    expect(await f.core.query("SELECT client_id FROM authorize_requests")).toEqual([{ client_id: CLIENT }]);
  });

  it("renders the error page when the saved request is missing", async () => {
    const f = fixture();
    const res = await call(f, "POST", "/authorize/resume", { headers: SAME_ORIGIN });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("invalid_authorize_request");
  });

  it("is not served on GET, so a cross-site link cannot complete someone's sign-in", async () => {
    const res = await call(fixture(), "GET", "/authorize/resume");
    expect(res.status).toBe(404);
  });
});

describe("/token and /userinfo", () => {
  const fixture = useFixture();

  it("exchanges a code for tokens that /userinfo accepts on GET and POST", async () => {
    const f = fixture();
    await seedAccess(f);
    const code = locationParams(await authorizeWithSession(f)).get("code") ?? "";
    const res = await exchange(f, code);
    expect(res.status).toBe(200);
    expect(res.headers.get("pragma")).toBe("no-cache");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 300, scope: "openid profile" });

    for (const method of ["GET", "POST"]) {
      const info = await call(f, method, "/userinfo", { headers: { authorization: `Bearer ${String(body["access_token"])}` } });
      expect(info.status).toBe(200);
      expect(await info.json()).toEqual({ sub: USER, name: "Alice" });
    }
  });

  it("does not let a reused code through", async () => {
    const f = fixture();
    await seedAccess(f);
    const code = locationParams(await authorizeWithSession(f)).get("code") ?? "";
    expect((await exchange(f, code)).status).toBe(200);
    const again = await exchange(f, code);
    expect(again.status).toBe(400);
    expect(await again.json()).toEqual({ error: "invalid_grant" });
  });

  it("answers a bad client with 401 invalid_client and a Basic challenge", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "POST", "/token", {
      headers: { authorization: basic(CLIENT, "wrong") },
      form: { grant_type: "authorization_code", code: "x", redirect_uri: REDIRECT_URI, code_verifier: PKCE.verifier },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(`Basic realm="${ISSUER}"`);
    expect(await res.json()).toEqual({ error: "invalid_client" });
  });

  it("refuses a body that is not a form", async () => {
    const f = fixture();
    await seedAccess(f);
    const res = await call(f, "POST", "/token", {
      headers: { authorization: basic(CLIENT, CONFIDENTIAL_SECRET), "content-type": "application/json" },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
  });

  it("answers /userinfo errors with WWW-Authenticate and no body", async () => {
    const f = fixture();
    const none = await call(f, "GET", "/userinfo");
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toBe(`Bearer realm="${ISSUER}"`);
    const bad = await call(f, "GET", "/userinfo", { headers: { authorization: "Bearer abc.def.ghi" } });
    expect(bad.status).toBe(401);
    expect(bad.headers.get("www-authenticate")).toContain('error="invalid_token"');
    expect(await bad.text()).toBe("");
  });

  it("is not served on GET", async () => {
    expect((await call(fixture(), "GET", "/token")).status).toBe(404);
  });
});

describe("POST /logout", () => {
  const fixture = useFixture();

  it("deletes the session row and clears the cookie", async () => {
    const f = fixture();
    await seedAccess(f);
    const session = await f.core.addSession(USER, CREDENTIAL);
    const res = await call(f, "POST", "/logout", { headers: SAME_ORIGIN, cookies: { [SESSION]: session } });
    expect(res.status).toBe(204);
    expect(setCookies(res).get(SESSION)).toMatch(/Max-Age=0/);
    expect(await f.core.query("SELECT * FROM sessions")).toEqual([]);
  });

  it("refuses a cross-site request and keeps the session", async () => {
    const f = fixture();
    await seedAccess(f);
    const session = await f.core.addSession(USER, CREDENTIAL);
    const res = await call(f, "POST", "/logout", { headers: { "sec-fetch-site": "cross-site" }, cookies: { [SESSION]: session } });
    expect(res.status).toBe(403);
    expect(await f.core.query("SELECT user_id FROM sessions")).toEqual([{ user_id: USER }]);
  });
});

describe("the IdP host exposes nothing else", () => {
  const fixture = useFixture();

  it.each([
    ["GET", "/v1/users"],
    ["POST", "/v1/clients"],
    ["GET", "/admin"],
    ["POST", "/.well-known/openid-configuration"],
  ])("%s %s is 404", async (method, path) => {
    const res = await call(fixture(), method, path, { headers: { origin: "https://app.example.com" } });
    expect(res.status).toBe(404);
  });
});
