// The HTTP layer of RP-Initiated Logout 1.0 (authentication.md, "RP からのログアウト"): the routes read the request,
// render the core's decision, and clear the cookie; the branches themselves are tested in the core.
import { describe, expect, it } from "vitest";
import { buildIdTokenClaims, loadSigningKeys, signIdToken, type IdTokenClaims } from "../src/domain/index.js";
import { CLIENT, CREDENTIAL, ISSUER, NOW, USER, call, seedAccess, setCookies, testSigningKey, useFixture, type Fixture } from "./fixture.js";

const SESSION = "__Host-session";
const SAME_ORIGIN = { "sec-fetch-site": "same-origin" } as const;
const RETURN = "https://app.example.com/bye";
const SIGNED_IN_AT = NOW - 60;

async function seed(f: Fixture): Promise<string> {
  await seedAccess(f, { postLogoutRedirectUris: [RETURN] });
  return f.core.addSession(USER, CREDENTIAL, SIGNED_IN_AT);
}

// Signed with the Worker's own key (the env's SIGNING_KEY_ED25519_CURRENT), as /token would.
async function hint(f: Fixture, overrides: Partial<Record<keyof IdTokenClaims, unknown>> = {}): Promise<string> {
  const keys = await loadSigningKeys({ ed25519Current: await testSigningKey() });
  const claims = {
    ...buildIdTokenClaims({
      issuer: f.core.deps.issuer,
      sub: USER,
      clientId: CLIENT,
      authTime: SIGNED_IN_AT,
      nonce: undefined,
      scopes: ["openid"],
      name: "A",
      now: NOW - 30,
    }),
    ...overrides,
  } as IdTokenClaims;
  return signIdToken(keys, "Ed25519", claims);
}

async function sessions(f: Fixture): Promise<number> {
  return (await f.core.query("SELECT 1 FROM sessions")).length;
}

/** The hidden fields of the confirmation form, in order. */
function hiddenFields(html: string): [string, string][] {
  return [...html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)].map((m) => [m[1] ?? "", m[2] ?? ""]);
}

describe("discovery", () => {
  const fixture = useFixture();

  it("advertises end_session_endpoint", async () => {
    const res = await call(fixture(), "GET", "/.well-known/openid-configuration");
    expect(await res.json()).toMatchObject({ end_session_endpoint: `${ISSUER}/end_session` });
  });
});

describe("GET /end_session", () => {
  const fixture = useFixture();

  it("ends the session for a hint from it and redirects with 302 to the registered URI with state", async () => {
    const f = fixture();
    const session = await seed(f);
    const query = new URLSearchParams({ id_token_hint: await hint(f), post_logout_redirect_uri: RETURN, state: "xyz" });
    const res = await call(f, "GET", `/end_session?${query}`, { cookies: { [SESSION]: session }, headers: { "sec-fetch-site": "cross-site" } });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${RETURN}?state=xyz`);
    expect(setCookies(res).get(SESSION)).toMatch(/Max-Age=0/);
    expect(await sessions(f)).toBe(0);
  });

  it("shows the signed-out page, not a redirect, for an unregistered post_logout_redirect_uri", async () => {
    const f = fixture();
    const session = await seed(f);
    const query = new URLSearchParams({ id_token_hint: await hint(f), post_logout_redirect_uri: "https://evil.example.com/", state: "s" });
    const res = await call(f, "GET", `/end_session?${query}`, { cookies: { [SESSION]: session } });
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    const html = await res.text();
    expect(html).toContain("signed out");
    expect(html).not.toContain("evil.example.com");
    expect(await sessions(f)).toBe(0);
  });

  it("asks for confirmation for a cross-site GET without a hint and keeps the session", async () => {
    const f = fixture();
    const session = await seed(f);
    const query = new URLSearchParams({ client_id: CLIENT, post_logout_redirect_uri: RETURN, state: '"><script>' });
    const res = await call(f, "GET", `/end_session?${query}`, { cookies: { [SESSION]: session }, headers: { "sec-fetch-site": "cross-site" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^text\/html/);
    expect(setCookies(res).has(SESSION)).toBe(false);
    const html = await res.text();
    expect(html).toContain('<form method="post" action="/end_session/confirm">');
    expect(html).not.toContain("<script");
    expect(hiddenFields(html)).toEqual([
      ["client_id", CLIENT],
      ["post_logout_redirect_uri", RETURN],
      ["state", "&quot;&gt;&lt;script&gt;"],
      ["ui_locales", "en"],
    ]);
    expect(await sessions(f)).toBe(1);
  });

  it("offers to stay signed in: a link to the IdP's account page that ends nothing and never returns to the RP", async () => {
    const f = fixture();
    const session = await seed(f);
    const query = new URLSearchParams({ client_id: CLIENT, post_logout_redirect_uri: RETURN, state: "s" });
    const html = await (await call(f, "GET", `/end_session?${query}`, { cookies: { [SESSION]: session } })).text();
    expect(html).toContain('<a href="/account">Stay signed in</a>');
    // The only way back to the RP is the form that ends the session.
    expect(html.split(RETURN)).toHaveLength(2);
    const ja = await (await call(f, "GET", "/end_session?ui_locales=ja", { cookies: { [SESSION]: session } })).text();
    expect(ja).toContain('<a href="/account">サインインしたままにする</a>');
  });

  it.each([
    ["a bad signature", async (f: Fixture) => `${(await hint(f)).slice(0, -4)}AAAA`, "invalid_id_token_hint"],
    ["another issuer", (f: Fixture) => hint(f, { iss: "https://other.example.com" }), "invalid_id_token_hint"],
  ])("refuses a hint with %s with a 400 error page and keeps the session", async (_, make, error) => {
    const f = fixture();
    const session = await seed(f);
    const query = new URLSearchParams({ id_token_hint: await make(f), post_logout_redirect_uri: RETURN });
    const res = await call(f, "GET", `/end_session?${query}`, { cookies: { [SESSION]: session } });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).toContain(error);
    expect(await sessions(f)).toBe(1);
  });

});

describe("POST /end_session", () => {
  const fixture = useFixture();

  it("reads the form, ends the session for a hint from it, and redirects with 303", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session?state=ignored", {
      cookies: { [SESSION]: session },
      form: { id_token_hint: await hint(f), post_logout_redirect_uri: RETURN, state: "s" },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${RETURN}?state=s`);
    expect(await sessions(f)).toBe(0);
  });

  it("asks for confirmation for a cross-site POST that carries no cookie", async () => {
    const f = fixture();
    await seed(f);
    const res = await call(f, "POST", "/end_session", { form: { id_token_hint: await hint(f) } });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('action="/end_session/confirm"');
    expect(await sessions(f)).toBe(1);
  });

  it("refuses a body that is not a form", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session", { cookies: { [SESSION]: session }, json: {} });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("invalid_request");
    expect(await sessions(f)).toBe(1);
  });
});

describe("POST /end_session/confirm", () => {
  const fixture = useFixture();

  it("ends the session and redirects with 303 once confirmed on the IdP's own page", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session/confirm", {
      headers: SAME_ORIGIN,
      cookies: { [SESSION]: session },
      form: { client_id: CLIENT, post_logout_redirect_uri: RETURN, state: "s", ui_locales: "en" },
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${RETURN}?state=s`);
    expect(setCookies(res).get(SESSION)).toMatch(/Max-Age=0/);
    expect(await sessions(f)).toBe(0);
  });

  it("shows the signed-out page when there is no registered redirect", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session/confirm", { headers: SAME_ORIGIN, cookies: { [SESSION]: session }, form: { ui_locales: "ja" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('<html lang="ja">');
    expect(await sessions(f)).toBe(0);
  });

  // The same-origin check's branches are tested on /authorize/resume (oidc.test.ts); this proves the route is guarded.
  it("refuses a cross-site request and keeps the session", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session/confirm", {
      headers: { "sec-fetch-site": "cross-site" },
      cookies: { [SESSION]: session },
      form: { client_id: CLIENT },
    });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("cross_origin_request");
    expect(await sessions(f)).toBe(1);
  });

  it("re-validates the carried values: an unregistered URI is not followed", async () => {
    const f = fixture();
    const session = await seed(f);
    const res = await call(f, "POST", "/end_session/confirm", {
      headers: SAME_ORIGIN,
      cookies: { [SESSION]: session },
      form: { client_id: CLIENT, post_logout_redirect_uri: "https://evil.example.com/" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("is not reachable with GET", async () => {
    const res = await call(fixture(), "GET", "/end_session/confirm");
    expect(res.status).toBe(404);
  });
});
