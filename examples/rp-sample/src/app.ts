// The routes: `/` (account or sign-in), `/login`, `/callback`, `POST /logout`, and `/signed-out`. Every protocol check lives in
// callback.ts, id-token.ts, and idp.ts; this file wires them to cookies and pages.
import { Hono, type Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { CallbackError, checkAuthorizationResponse, constantTimeEqual } from "./callback.js";
import { loadConfig, type Config, type Env } from "./config.js";
import { ConfigError, IdpError } from "./errors.js";
import {
  accountPage,
  errorPage,
  idTokenViewFromJwt,
  logoutContentSecurityPolicy,
  logoutFormPage,
  postLogoutPage,
  signedOutPage,
  type SessionView,
} from "./html.js";
import { IdTokenError } from "./id-token.js";
import { createIdpClient, type EndSessionEndpoint, type Fetcher, type IdpClient } from "./idp.js";
import { pkceChallenge, randomToken } from "./pkce.js";
import { seal, unseal } from "./sealed.js";

/** The login in progress, between /login and /callback. */
export const FLOW_COOKIE = "__Host-rp-sample-flow";
/** The signed-in session. */
export const SESSION_COOKIE = "__Host-rp-sample-session";
/** The logout in progress, between POST /logout and /signed-out: the state sent to the IdP. */
export const LOGOUT_COOKIE = "__Host-rp-sample-logout";
/** A login, or a logout's return from the IdP, must come back within 10 minutes. */
export const FLOW_SECONDS = 600;
/** The RP session's absolute lifetime; the IdP's own session is also 1 hour (docs/design/tokens.md). */
export const SESSION_SECONDS = 3600;
/** The largest cookie name and value a browser must keep (RFC 6265bis §5.6). */
export const MAX_COOKIE_OCTETS = 4096;

/** What the routes need besides the bindings. */
export type AppOptions = {
  /** The outbound fetch to the IdP. */
  readonly fetch: Fetcher;
  /** The clock, in Unix seconds. */
  readonly now: () => number;
};

type AppEnv = { Bindings: Env; Variables: { config: Config; idp: IdpClient } };

// HttpOnly, Secure, SameSite=Lax, Path=/, no Domain: the __Host- prefix makes the browser enforce the last three.
// Lax, not Strict: the callback is a top-level navigation from the IdP, which must carry the flow cookie.
const COOKIE_OPTIONS = { httpOnly: true, secure: true, sameSite: "Lax", path: "/" } as const;

function log(entry: Readonly<Record<string, string | number>>): void {
  console.log(JSON.stringify(entry));
}

function refuse(c: Context<AppEnv>, status: 400 | 403 | 404 | 405 | 500 | 502, message: string, detail?: string): Response {
  return c.html(errorPage(message, detail), status);
}

/**
 * Checks that a state-changing POST comes from this RP's own page: Sec-Fetch-Site must be same-origin, or, without
 * it, Origin must be this origin. Same-site is not enough: in the workers_dev mode every Worker of the account,
 * the IdP included, is the same site.
 *
 * @param request The request.
 * @param origin This RP's origin.
 * @returns Whether the request is same-origin.
 */
function isSameOrigin(request: Request, origin: string): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null) return site === "same-origin";
  return request.headers.get("origin") === origin;
}

// A session keeps the ID token once, as the logout hint, and the page's claims are read from it. A session sealed
// before this RP kept the hint holds the claims instead (and no hint), and still reads.
function readSession(data: Readonly<Record<string, unknown>> | undefined): SessionView | undefined {
  const hint = data?.idTokenHint;
  const idToken = typeof hint === "string" ? idTokenViewFromJwt(hint) : data?.idToken;
  const userinfo = data?.userinfo;
  if (typeof idToken !== "object" || idToken === null || typeof userinfo !== "object" || userinfo === null) return undefined;
  return { idToken: idToken as Record<string, unknown>, userinfo: userinfo as Record<string, unknown> };
}

/**
 * Builds the routes.
 *
 * @param options The outbound fetch and the clock.
 * @returns The Hono app.
 */
export function createApp(options: AppOptions): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const idpFor = createIdpClient(options.fetch, options.now);

  app.onError((error, c) => {
    if (error instanceof ConfigError) {
      log({ result: "refused", reason: "config", detail: error.message });
      return c.text("The relying party is misconfigured.", 500);
    }
    if (error instanceof CallbackError) {
      log({ route: "callback", result: "refused", reason: error.reason });
      if (error.reason === "idp_error") return refuse(c, 400, "IdP がサインインを完了しませんでした。", error.idpError);
      return refuse(c, 400, "サインインの応答を確かめられませんでした。最初からやり直してください。");
    }
    if (error instanceof IdpError || error instanceof IdTokenError) {
      log({ result: "refused", reason: error.name, detail: error.message });
      return refuse(c, 502, "IdP の応答を確かめられませんでした。");
    }
    log({ result: "error", reason: error.name });
    return c.text("Internal Server Error", 500);
  });

  // Configuration first: a missing setting refuses every route. Then only this Worker's own https origin is served.
  app.use(async (c, next) => {
    const config = await loadConfig(c.env);
    const url = new URL(c.req.url);
    const own = new URL(config.origin);
    if (url.protocol === "http:" && url.host === own.host) {
      // No cookie of this RP travels over http (they are __Host-, so Secure); send the browser to https.
      if (c.req.method !== "GET" && c.req.method !== "HEAD") return c.text("Use https.", 400);
      return c.redirect(`${config.origin}${url.pathname}${url.search}`, 308);
    }
    if (url.origin !== config.origin) return c.text("Not Found", 404);
    c.set("config", config);
    c.set("idp", idpFor(config));
    await next();
  });

  app.get("/", async (c) => {
    const { sessionKey } = c.get("config");
    const session = readSession(await unseal(sessionKey, SESSION_COOKIE, getCookie(c, SESSION_COOKIE), options.now()));
    return c.html(session === undefined ? signedOutPage() : accountPage(session));
  });

  app.get("/login", async (c) => {
    const config = c.get("config");
    const discovery = await c.get("idp").discover();
    const state = randomToken();
    const nonce = randomToken();
    const verifier = randomToken();
    // One login at a time per browser: a second /login replaces the first one's cookie, and the first callback fails.
    const flow = await seal(config.sessionKey, FLOW_COOKIE, { state, nonce, verifier }, options.now() + FLOW_SECONDS);
    setCookie(c, FLOW_COOKIE, flow, { ...COOKIE_OPTIONS, maxAge: FLOW_SECONDS });
    const authorization = new URL(discovery.authorizationEndpoint);
    // RFC 6749 §3.1: a query already in the endpoint URI MUST be retained, so each parameter is added to it.
    const params: Readonly<Record<string, string>> = {
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: "openid profile",
      state,
      nonce,
      code_challenge: await pkceChallenge(verifier),
      code_challenge_method: "S256",
    };
    for (const [name, value] of Object.entries(params)) authorization.searchParams.set(name, value);
    log({ route: "login", result: "redirected" });
    return c.redirect(authorization.href, 302);
  });

  app.get("/callback", async (c) => {
    const config = c.get("config");
    const flow = await unseal(config.sessionKey, FLOW_COOKIE, getCookie(c, FLOW_COOKIE), options.now());
    // Single use, whatever happens next: set before any check, so the error responses clear it too.
    deleteCookie(c, FLOW_COOKIE, COOKIE_OPTIONS);
    const { state, nonce, verifier } = flow ?? {};
    if (typeof state !== "string" || typeof nonce !== "string" || typeof verifier !== "string") throw new CallbackError("state");
    const { code } = checkAuthorizationResponse(new URL(c.req.url).searchParams, state, config.issuer);
    const { idTokenJwt, userinfo } = await c.get("idp").redeem({ code, verifier, nonce });
    // The verified ID token is kept as issued: the logout's id_token_hint (RP-Initiated Logout 1.0 §2, RECOMMENDED)
    // and the source of the claims the account page shows (readSession). It is sealed like the rest.
    const session = { userinfo, idTokenHint: idTokenJwt };
    const sealed = await seal(config.sessionKey, SESSION_COOKIE, session, options.now() + SESSION_SECONDS);
    // RFC 6265bis §5.6: a browser ignores a cookie whose name and value exceed 4096 octets. Refuse here instead, so
    // a large /userinfo (multibyte names included: measured in UTF-8 octets) fails visibly, not as a silent loop.
    if (new TextEncoder().encode(`${SESSION_COOKIE}=${sealed}`).length > MAX_COOKIE_OCTETS) {
      throw new IdpError("session: the claims and /userinfo exceed the 4096-octet cookie limit");
    }
    setCookie(c, SESSION_COOKIE, sealed, {
      ...COOKIE_OPTIONS,
      maxAge: SESSION_SECONDS,
    });
    log({ route: "callback", result: "signed_in" });
    return c.redirect("/", 303);
  });

  // RP-Initiated Logout 1.0: this RP's session ends here whatever happens next, then the browser takes the logout
  // request to the IdP so that the IdP's session ends too and the next sign-in asks for the passkey again.
  app.post("/logout", async (c) => {
    const config = c.get("config");
    if (!isSameOrigin(c.req.raw, config.origin)) {
      log({ route: "logout", result: "refused", reason: "origin" });
      return refuse(c, 403, "このページからのログアウトだけを受け付けます。");
    }
    const session = await unseal(config.sessionKey, SESSION_COOKIE, getCookie(c, SESSION_COOKIE), options.now());
    deleteCookie(c, SESSION_COOKIE, COOKIE_OPTIONS);
    // Without a session there is no ID token to send as the hint, and nothing of this RP to end.
    if (session === undefined) {
      log({ route: "logout", result: "signed_out", scope: "rp" });
      return c.redirect("/", 303);
    }
    let endSession: EndSessionEndpoint;
    try {
      ({ endSession } = await c.get("idp").discover());
    } catch (error) {
      if (!(error instanceof IdpError)) throw error;
      // The RP session is already gone (the cookie is cleared above); say so, and that the IdP's may remain.
      log({ route: "logout", result: "refused", reason: "discovery", detail: error.message });
      return refuse(c, 502, "IdP に連絡できなかったので、この RP からだけログアウトしました。この RP のセッションは終わっています。IdP のセッションは残っているかもしれません。");
    }
    if (endSession.kind === "none") {
      log({ route: "logout", result: "signed_out", scope: "rp" });
      return c.redirect("/", 303);
    }
    if (endSession.kind === "invalid") {
      log({ route: "logout", result: "refused", reason: "end_session_endpoint" });
      return refuse(c, 502, "IdP のログアウトの宛先を確かめられなかったので、この RP からだけログアウトしました。この RP のセッションは終わっています。IdP のセッションは残っているかもしれません。");
    }
    // state is checked at /signed-out against this sealed, single-use cookie (see there).
    const state = randomToken();
    setCookie(c, LOGOUT_COOKIE, await seal(config.sessionKey, LOGOUT_COOKIE, { state }, options.now() + FLOW_SECONDS), {
      ...COOKIE_OPTIONS,
      maxAge: FLOW_SECONDS,
    });
    // §2: id_token_hint (RECOMMENDED), the registered post_logout_redirect_uri (§3), state, and client_id. A sealed
    // session from before this RP kept the hint has none: the IdP then asks the user to confirm (§2 MUST).
    const hint = session.idTokenHint;
    const fields: [string, string][] = [];
    if (typeof hint === "string") fields.push(["id_token_hint", hint]);
    fields.push(["post_logout_redirect_uri", config.postLogoutRedirectUri], ["state", state], ["client_id", config.clientId]);
    // A form POST, not a redirect: the ID token stays out of URLs, browser history, and access logs (§2 allows both).
    c.header("content-security-policy", logoutContentSecurityPolicy(new URL(endSession.url).origin));
    log({ route: "logout", result: "signed_out", scope: "rp_and_idp" });
    return c.html(logoutFormPage(endSession.url, fields));
  });

  // The post_logout_redirect_uri. The IdP appends the state this RP sent (§3). Matching it against the sealed cookie
  // proves that this browser asked for this logout: without the check, any link to /signed-out could claim that the
  // IdP session ended, which on a shared device is the one thing the user must be able to trust. The cookie is single
  // use and the RP session is already gone, so a failed check only changes what the page says.
  app.get("/signed-out", async (c) => {
    const config = c.get("config");
    const logout = await unseal(config.sessionKey, LOGOUT_COOKIE, getCookie(c, LOGOUT_COOKIE), options.now());
    deleteCookie(c, LOGOUT_COOKIE, COOKIE_OPTIONS);
    const returned = new URL(c.req.url).searchParams.getAll("state");
    const expected = logout?.state;
    const confirmed = returned.length === 1 && typeof expected === "string" && constantTimeEqual(returned[0] ?? "", expected);
    log({ route: "signed_out", result: confirmed ? "confirmed" : "refused" });
    return c.html(postLogoutPage(confirmed), confirmed ? 200 : 400);
  });

  app.all("/logout", (c) => {
    c.header("allow", "POST");
    return refuse(c, 405, "ログアウトはボタンから行ってください。");
  });

  app.notFound((c) => c.text("Not Found", 404));
  return app;
}
