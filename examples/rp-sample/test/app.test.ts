import { describe, expect, it, vi } from "vitest";
import { createHandler, type Handler } from "../src/index.js";
import { CLIENT_ID, ENV, FakeIdp, ISSUER, ORIGIN, SUB, type FakeIdpOptions } from "./support/fake-idp.js";

const FLOW_COOKIE = "__Host-rp-sample-flow";
const SESSION_COOKIE = "__Host-rp-sample-session";
const LOGOUT_COOKIE = "__Host-rp-sample-logout";
const START = 1_800_000_000;

type Rig = { readonly idp: FakeIdp; readonly handler: Handler; readonly clock: { now: number } };

async function rig(options: FakeIdpOptions = {}): Promise<Rig> {
  const clock = { now: START };
  const idp = await FakeIdp.create(options, () => clock.now);
  return { idp, clock, handler: createHandler({ fetch: idp.fetch, now: () => clock.now }) };
}

function call(rig: Rig, path: string, init: RequestInit & { cookies?: Record<string, string> } = {}, env = ENV): Promise<Response> {
  const headers = new Headers(init.headers);
  const cookies = Object.entries(init.cookies ?? {});
  if (cookies.length > 0) headers.set("cookie", cookies.map(([name, value]) => `${name}=${value}`).join("; "));
  return rig.handler.fetch(new Request(new URL(path, ORIGIN), { ...init, headers, redirect: "manual" }), env);
}

/** The Set-Cookie attributes of one cookie, keyed by lowercase name; `value` holds the cookie's value. */
function setCookie(response: Response, name: string): Map<string, string> | undefined {
  const line = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`));
  if (line === undefined) return undefined;
  const [first, ...attributes] = line.split(";").map((part) => part.trim());
  const result = new Map<string, string>([["value", first?.slice(name.length + 1) ?? ""]]);
  for (const attribute of attributes) {
    const [key, value] = attribute.split("=");
    result.set(key?.toLowerCase() ?? "", value ?? "");
  }
  return result;
}

function cookieValue(response: Response, name: string): string {
  const value = setCookie(response, name)?.get("value");
  if (value === undefined || value === "") throw new Error(`no ${name} cookie`);
  return value;
}

/** /login, the IdP's /authorize, and the callback's URL and flow cookie. */
async function startLogin(r: Rig): Promise<{ callback: URL; flow: string; authorization: URL }> {
  const login = await call(r, "/login");
  expect(login.status).toBe(302);
  const authorization = new URL(login.headers.get("location") ?? "");
  return { callback: r.idp.authorize(authorization.href), flow: cookieValue(login, FLOW_COOKIE), authorization };
}

/** A full sign-in; returns the session cookie value. */
async function signIn(r: Rig): Promise<string> {
  const { callback, flow } = await startLogin(r);
  const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
  expect(response.status).toBe(303);
  return cookieValue(response, SESSION_COOKIE);
}

describe("GET /", () => {
  it("offers a sign-in when there is no session", async () => {
    const r = await rig();
    const response = await call(r, "/");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^text\/html; charset=utf-8/i);
    const html = await response.text();
    expect(html).toContain('href="/login"');
    expect(html).not.toContain('action="/logout"');
    expect(r.idp.requests).toHaveLength(0);
  });

  it("sets the security headers on every page", async () => {
    const r = await rig();
    const response = await call(r, "/");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });
});

describe("GET /login", () => {
  it("redirects to the discovered authorization endpoint with PKCE S256, state, nonce, and scope openid profile", async () => {
    const r = await rig();
    const { authorization } = await startLogin(r);
    expect(`${authorization.origin}${authorization.pathname}`).toBe(`${ISSUER}/authorize`);
    const params = authorization.searchParams;
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe(`${ORIGIN}/callback`);
    expect(params.get("scope")).toBe("openid profile");
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(params.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(params.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(params.get("state")).not.toBe(params.get("nonce"));
  });

  it("retains a query already in the authorization endpoint (RFC 6749 §3.1)", async () => {
    const r = await rig({ discovery: { authorization_endpoint: `${ISSUER}/authorize?tenant=a&locale=ja` } });
    const { authorization, callback, flow } = await startLogin(r);
    expect(authorization.searchParams.get("tenant")).toBe("a");
    expect(authorization.searchParams.get("locale")).toBe("ja");
    expect(authorization.searchParams.get("response_type")).toBe("code");
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(303);
  });

  it("keeps state, nonce, and the verifier in a short-lived, sealed __Host- cookie", async () => {
    const r = await rig();
    const login = await call(r, "/login");
    const cookie = setCookie(login, FLOW_COOKIE);
    expect(cookie?.get("httponly")).toBe("");
    expect(cookie?.get("secure")).toBe("");
    expect(cookie?.get("samesite")).toBe("Lax");
    expect(cookie?.get("path")).toBe("/");
    expect(cookie?.has("domain")).toBe(false);
    expect(Number(cookie?.get("max-age"))).toBeGreaterThan(0);
    expect(Number(cookie?.get("max-age"))).toBeLessThanOrEqual(600);
    const params = new URL(login.headers.get("location") ?? "").searchParams;
    expect(cookie?.get("value")).not.toContain(params.get("state"));
    expect(cookie?.get("value")).not.toContain(params.get("nonce"));
  });

  it("names itself to the IdP: workers.dev refuses library-default User-Agents", async () => {
    const r = await rig();
    await signIn(r);
    expect(r.idp.requests.length).toBeGreaterThan(0);
    for (const request of r.idp.requests) expect(request.headers.get("user-agent")).toMatch(/^idp-rp-sample\//);
  });

  it("refuses an IdP whose discovery names another issuer", async () => {
    const r = await rig({ discovery: { issuer: "https://evil.example" } });
    const response = await call(r, "/login");
    expect(response.status).toBe(502);
    expect(response.headers.get("location")).toBeNull();
  });

  it("refuses an IdP that does not support S256", async () => {
    const r = await rig({ discovery: { code_challenge_methods_supported: ["plain"] } });
    expect((await call(r, "/login")).status).toBe(502);
  });
});

describe("GET /callback", () => {
  it("exchanges the code as a confidential client, validates the ID token, calls /userinfo, and sets the session", async () => {
    const r = await rig();
    const { callback, flow } = await startLogin(r);
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");

    const token = r.idp.requests.find((request) => request.url === `${ISSUER}/token`);
    expect(token?.method).toBe("POST");
    expect(token?.headers.get("authorization")).toMatch(/^Basic /);
    const body = new URLSearchParams(token?.body);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("redirect_uri")).toBe(`${ORIGIN}/callback`);
    // client_secret_basic only: the secret never goes in the body.
    expect(body.has("client_secret")).toBe(false);
    expect(r.idp.requests.some((request) => request.url === `${ISSUER}/userinfo`)).toBe(true);

    const session = setCookie(response, SESSION_COOKIE);
    expect(session?.get("httponly")).toBe("");
    expect(session?.get("secure")).toBe("");
    expect(session?.get("samesite")).toBe("Lax");
    expect(session?.get("path")).toBe("/");
    expect(session?.get("value")).not.toContain(SUB);
    // The flow cookie is single use.
    expect(setCookie(response, FLOW_COOKIE)?.get("max-age")).toBe("0");
  });

  it("shows the account once signed in: sub, the ID token claims, the /userinfo response, and a logout button", async () => {
    const r = await rig();
    const session = await signIn(r);
    const html = await (await call(r, "/", { cookies: { [SESSION_COOKIE]: session } })).text();
    expect(html).toContain(SUB);
    expect(html).toContain("Alice");
    expect(html).toContain(ISSUER);
    expect(html).toContain('action="/logout"');
    expect(html).toContain('method="post"');
  });

  it("escapes what the IdP returns before writing it into the page", async () => {
    const r = await rig({ idTokenClaims: { name: "<script>alert(1)</script>" }, userinfo: { sub: SUB, name: '"><img src=x onerror=alert(1)>' } });
    const session = await signIn(r);
    const html = await (await call(r, "/", { cookies: { [SESSION_COOKIE]: session } })).text();
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  async function refusedCallback(r: Rig, change: (callback: URL) => void, cookies?: Record<string, string>): Promise<Response> {
    const { callback, flow } = await startLogin(r);
    change(callback);
    return call(r, `${callback.pathname}${callback.search}`, { cookies: cookies ?? { [FLOW_COOKIE]: flow } });
  }

  it.each<[string, (callback: URL) => void]>([
    ["another state", (callback) => callback.searchParams.set("state", "forged")],
    ["no iss (RFC 9207)", (callback) => callback.searchParams.delete("iss")],
    ["another iss (RFC 9207 mix-up)", (callback) => callback.searchParams.set("iss", "https://evil.example")],
    ["an error from the IdP", (callback) => {
      callback.searchParams.delete("code");
      callback.searchParams.set("error", "access_denied");
    }],
  ])("refuses %s without calling the token endpoint and without a session", async (_name, change) => {
    const r = await rig();
    const response = await refusedCallback(r, change);
    expect(response.status).toBe(400);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
    expect(setCookie(response, FLOW_COOKIE)?.get("max-age")).toBe("0");
    expect(r.idp.requests.some((request) => request.url.endsWith("/token"))).toBe(false);
  });

  it("refuses a callback without the flow cookie (another browser, or an expired login)", async () => {
    const r = await rig();
    const response = await refusedCallback(r, () => undefined, {});
    expect(response.status).toBe(400);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
  });

  it("refuses an expired flow cookie", async () => {
    const r = await rig();
    const { callback, flow } = await startLogin(r);
    r.clock.now += 601;
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(400);
  });

  it.each<[string, FakeIdpOptions, number]>([
    ["a token endpoint error", { tokenStatus: 400 }, 502],
    ["an ID token with another nonce", { idTokenClaims: { nonce: "replayed" } }, 502],
    ["an ID token for another client", { idTokenClaims: { aud: "other-client" } }, 502],
    ["an ID token from another issuer", { idTokenClaims: { iss: "https://evil.example" } }, 502],
    ["an expired ID token", { idTokenClaims: { exp: START - 3600, iat: START - 3900 } }, 502],
    ["an ID token signed by a key outside the JWKS", { signWithForeignKey: true }, 502],
    // OIDC Core §5.3.2: the UserInfo sub MUST match the ID token's, or the response is not used.
    ["a /userinfo response for another user", { userinfo: { sub: "someone-else", name: "Mallory" } }, 502],
  ])("refuses %s and sets no session", async (_name, options, status) => {
    const r = await rig(options);
    const { callback, flow } = await startLogin(r);
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(status);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
    // The error page is built by onError; the flow cookie's deletion set before the throw must survive it.
    expect(setCookie(response, FLOW_COOKIE)?.get("max-age")).toBe("0");
  });

  it.each<[string, FakeIdpOptions]>([
    ["a token response with a lowercase token_type (case-insensitive, RFC 6749 §5.1)", { tokenResponse: { token_type: "bearer" } }],
    ["a token response with unknown members (ignored, RFC 6749 §5.1)", { tokenResponse: { refresh_hint: "x", at_hash: "ignored" } }],
    ["a token response with a charset parameter", { contentType: { token: "application/json; charset=UTF-8" } }],
    ["a /userinfo response in upper case media type", { contentType: { userinfo: "Application/JSON" } }],
  ])("accepts %s", async (_name, options) => {
    const r = await rig(options);
    await signIn(r);
  });

  it.each<[string, FakeIdpOptions]>([
    ["another token_type (RFC 6749 §7.1)", { tokenResponse: { token_type: "mac" } }],
    ["no token_type", { tokenResponse: { token_type: undefined } }],
    ["no access_token", { tokenResponse: { access_token: undefined } }],
    ["no id_token (OIDC Core §3.1.3.3)", { tokenResponse: { id_token: undefined } }],
    ["a token response that is not application/json", { contentType: { token: "application/jsonx" } }],
    ["a /userinfo response that is not application/json (OIDC Core §5.3.2)", { contentType: { userinfo: "application/jwt" } }],
    ["a /userinfo response without sub", { userinfo: { name: "Alice" } }],
    ["a JWKS that is not application/json", { contentType: { jwks: "text/plain" } }],
  ])("refuses %s, sets no session, and clears the flow cookie", async (_name, options) => {
    const r = await rig(options);
    const { callback, flow } = await startLogin(r);
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(502);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
    expect(setCookie(response, FLOW_COOKIE)?.get("max-age")).toBe("0");
  });

  it("refuses discovery that is not application/json", async () => {
    const r = await rig({ contentType: { discovery: "application/jsonx" } });
    expect((await call(r, "/login")).status).toBe(502);
  });

  it("logs the token endpoint's error code, never its description", async () => {
    const r = await rig({ tokenStatus: 400 });
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });
    try {
      const { callback, flow } = await startLogin(r);
      await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    } finally {
      spy.mockRestore();
    }
    expect(lines.some((line) => line.includes("token: status 400 error invalid_grant"))).toBe(true);
  });

  // RFC 6265bis §5.6: a browser drops a cookie whose name and value exceed 4096 octets, counted in UTF-8.
  it("keeps a session whose claims fit the cookie limit", async () => {
    const r = await rig({ userinfo: { sub: SUB, name: "a".repeat(1000) } });
    await signIn(r);
  });

  it("refuses a sign-in whose session would exceed 4096 octets, counting multibyte claims in UTF-8", async () => {
    // 1000 characters, as the ASCII case above, but 3000 octets in UTF-8.
    const r = await rig({ userinfo: { sub: SUB, name: "あ".repeat(1000) } });
    const { callback, flow } = await startLogin(r);
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(502);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
    expect(setCookie(response, FLOW_COOKIE)?.get("max-age")).toBe("0");
  });

  it("counts the kept ID token (the logout hint) against the 4096-octet limit and fails clearly", async () => {
    // The name is in the claims the page shows and again inside the raw ID token: together over the limit.
    const r = await rig({ idTokenClaims: { name: "a".repeat(1200) } });
    const { callback, flow } = await startLogin(r);
    const response = await call(r, `${callback.pathname}${callback.search}`, { cookies: { [FLOW_COOKIE]: flow } });
    expect(response.status).toBe(502);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
  });

  it("does not show the IdP's error description, only a plain error code", async () => {
    const r = await rig();
    const response = await refusedCallback(r, (callback) => {
      callback.searchParams.delete("code");
      callback.searchParams.set("error", "access_denied");
      callback.searchParams.set("error_description", "<b>injected</b>");
    });
    const html = await response.text();
    expect(html).toContain("access_denied");
    expect(html).not.toContain("injected");
  });
});

describe("the session", () => {
  it("ends at its expiry", async () => {
    const r = await rig();
    const session = await signIn(r);
    r.clock.now += 3601;
    const html = await (await call(r, "/", { cookies: { [SESSION_COOKIE]: session } })).text();
    expect(html).toContain('href="/login"');
    expect(html).not.toContain(SUB);
  });

  it("is ignored when tampered with", async () => {
    const r = await rig();
    const session = await signIn(r);
    // The second-to-last character always carries 6 bits of the tag; replace it with a different character.
    const tampered = `${session.slice(0, -2)}${session.at(-2) === "A" ? "B" : "A"}${session.slice(-1)}`;
    expect(tampered).not.toBe(session);
    const html = await (await call(r, "/", { cookies: { [SESSION_COOKIE]: tampered } })).text();
    expect(html).toContain('href="/login"');
  });

  it("cannot be replaced by the flow cookie's value", async () => {
    const r = await rig();
    const { flow } = await startLogin(r);
    const html = await (await call(r, "/", { cookies: { [SESSION_COOKIE]: flow } })).text();
    expect(html).toContain('href="/login"');
  });
});

/** The hidden fields of the logout form, by name. */
function formFields(html: string): Map<string, string> {
  return new Map([...html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)].map((m) => [m[1] ?? "", m[2] ?? ""]));
}

/** Signs in, then posts /logout from the account page. */
async function logout(r: Rig): Promise<Response> {
  const session = await signIn(r);
  return call(r, "/logout", { method: "POST", headers: { "sec-fetch-site": "same-origin" }, cookies: { [SESSION_COOKIE]: session } });
}

async function sha256Base64(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return btoa(String.fromCharCode(...digest));
}

describe("POST /logout (RP-Initiated Logout 1.0)", () => {
  it("clears the RP session and posts the logout request to the discovered end_session_endpoint", async () => {
    const r = await rig();
    const response = await logout(r);
    expect(response.status).toBe(200);
    expect(setCookie(response, SESSION_COOKIE)?.get("max-age")).toBe("0");
    const html = await response.text();
    expect(html).toContain(`<form method="post" action="${ISSUER}/end_session">`);
    const fields = formFields(html);
    // §2: the ID token the IdP issued as the hint, the registered return address, this RP's client_id, and a state.
    expect(fields.get("id_token_hint")).toBe(r.idp.lastIdToken);
    expect(fields.get("post_logout_redirect_uri")).toBe(`${ORIGIN}/signed-out`);
    expect(fields.get("client_id")).toBe(CLIENT_ID);
    expect(fields.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect([...fields.keys()].sort()).toEqual(["client_id", "id_token_hint", "post_logout_redirect_uri", "state"]);
  });

  it("keeps the ID token out of the URL: the request is a form POST, never a redirect", async () => {
    const r = await rig();
    const response = await logout(r);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("allows exactly the auto-submit script by hash and form posts only to the IdP and back to itself", async () => {
    const r = await rig();
    const response = await logout(r);
    const html = await response.text();
    const script = /<script>([^<]*)<\/script>/.exec(html)?.[1] ?? "";
    expect(script).toBe("document.forms[0].submit();");
    const csp = response.headers.get("content-security-policy") ?? "";
    expect(csp).toContain(`script-src 'sha256-${await sha256Base64(script)}'`);
    expect(csp).toContain(`form-action ${ISSUER} 'self'`);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-inline' 'unsafe-eval");
    // Without script the button still submits the form.
    expect(html).toContain('<button type="submit">');
  });

  it("keeps the returned state in a sealed, single-use __Host- cookie", async () => {
    const r = await rig();
    const response = await logout(r);
    const cookie = setCookie(response, LOGOUT_COOKIE);
    expect(cookie?.get("value")).toMatch(/^v1\./);
    expect(cookie?.has("httponly")).toBe(true);
    expect(cookie?.has("secure")).toBe(true);
    expect(cookie?.get("samesite")).toBe("Lax");
    expect(cookie?.get("path")).toBe("/");
    expect(cookie?.get("max-age")).toBe("600");
    expect(await response.clone().text()).not.toContain(cookie?.get("value") ?? "-");
  });

  it("falls back to a local logout when discovery has no end_session_endpoint", async () => {
    const r = await rig({ discovery: { end_session_endpoint: undefined } });
    const response = await logout(r);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(setCookie(response, SESSION_COOKIE)?.get("max-age")).toBe("0");
    expect(setCookie(response, LOGOUT_COOKIE)).toBeUndefined();
  });

  it("refuses an end_session_endpoint that is not https, and still clears the RP session", async () => {
    const r = await rig({ discovery: { end_session_endpoint: "http://idp.team-1.workers.dev/end_session" } });
    const response = await logout(r);
    expect(response.status).toBe(502);
    expect(setCookie(response, SESSION_COOKIE)?.get("max-age")).toBe("0");
    expect(await response.text()).toContain("この RP からだけログアウトしました");
  });

  it("logs out locally when there is no RP session: there is no hint to send", async () => {
    const r = await rig();
    const response = await call(r, "/logout", { method: "POST", headers: { "sec-fetch-site": "same-origin" } });
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(r.idp.requests).toHaveLength(0);
  });

  it("accepts the Origin header when Sec-Fetch-Site is absent", async () => {
    const r = await rig();
    const response = await call(r, "/logout", { method: "POST", headers: { origin: ORIGIN } });
    expect(response.status).toBe(303);
  });

  it.each<[string, Record<string, string>]>([
    // Same-site is not enough: in the workers_dev mode the IdP and other Workers of the account share the site.
    ["a same-site post", { "sec-fetch-site": "same-site" }],
    ["a cross-site post", { "sec-fetch-site": "cross-site" }],
    ["another Origin", { origin: "https://evil.example" }],
    ["the IdP's Origin", { origin: ISSUER }],
    ["neither header", {}],
  ])("refuses %s", async (_name, headers) => {
    const r = await rig();
    const response = await call(r, "/logout", { method: "POST", headers });
    expect(response.status).toBe(403);
    expect(setCookie(response, SESSION_COOKIE)).toBeUndefined();
  });

  it("is POST only", async () => {
    const r = await rig();
    expect((await call(r, "/logout")).status).toBe(405);
  });
});

describe("GET /signed-out (the post-logout redirect URI)", () => {
  /** Logs out and returns the state and the logout cookie the browser would carry back. */
  async function loggedOut(r: Rig): Promise<{ state: string; cookie: string }> {
    const response = await logout(r);
    const state = formFields(await response.clone().text()).get("state") ?? "";
    return { state, cookie: cookieValue(response, LOGOUT_COOKIE) };
  }

  it("confirms the IdP logout when the returned state matches, and clears the cookie (single use)", async () => {
    const r = await rig();
    const { state, cookie } = await loggedOut(r);
    const response = await call(r, `/signed-out?state=${state}`, { cookies: { [LOGOUT_COOKIE]: cookie } });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("IdP からもサインアウトしました");
    expect(setCookie(response, LOGOUT_COOKIE)?.get("max-age")).toBe("0");
  });

  it.each<[string, (state: string) => string, boolean]>([
    ["another state", () => "x".repeat(43), true],
    ["no state", () => "", true],
    ["a repeated state", (state) => `state=${state}&state=${state}`, true],
    ["no logout cookie", (state) => `state=${state}`, false],
  ])("does not claim an IdP logout for %s", async (_name, query, withCookie) => {
    const r = await rig();
    const { state, cookie } = await loggedOut(r);
    const built = query(state);
    const search = built.startsWith("state=") || built === "" ? built : `state=${built}`;
    const response = await call(r, `/signed-out?${search}`, withCookie ? { cookies: { [LOGOUT_COOKIE]: cookie } } : {});
    expect(response.status).toBe(400);
    const html = await response.text();
    expect(html).not.toContain("IdP からもサインアウトしました");
    expect(html).toContain("この RP のセッションは消してあります");
  });

  it("refuses an expired logout cookie", async () => {
    const r = await rig();
    const { state, cookie } = await loggedOut(r);
    r.clock.now += 601;
    const response = await call(r, `/signed-out?state=${state}`, { cookies: { [LOGOUT_COOKIE]: cookie } });
    expect(response.status).toBe(400);
  });

  it("refuses a session cookie replayed as the logout cookie", async () => {
    const r = await rig();
    const session = await signIn(r);
    const response = await call(r, "/signed-out?state=x", { cookies: { [LOGOUT_COOKIE]: session } });
    expect(response.status).toBe(400);
  });
});

describe("the edges", () => {
  it("fails closed on missing configuration, on every route", async () => {
    const r = await rig();
    for (const path of ["/", "/login", "/callback"]) {
      const response = await call(r, path, {}, { ...ENV, CLIENT_SECRET: undefined });
      expect(response.status).toBe(500);
      expect(await response.text()).toContain("misconfigured");
    }
    expect(r.idp.requests).toHaveLength(0);
  });

  it("answers only on its own origin", async () => {
    const r = await rig();
    const response = await r.handler.fetch(new Request("https://rp-sample-preview.team-1.workers.dev/"), ENV);
    expect(response.status).toBe(404);
  });

  it("redirects a plain http GET to https on its own origin", async () => {
    const r = await rig();
    const response = await r.handler.fetch(new Request("http://rp-sample.team-1.workers.dev/login?x=1", { redirect: "manual" }), ENV);
    expect(response.status).toBe(308);
    expect(response.headers.get("location")).toBe(`${ORIGIN}/login?x=1`);
  });

  it("answers 404 on an unknown path", async () => {
    const r = await rig();
    expect((await call(r, "/admin")).status).toBe(404);
  });
});
