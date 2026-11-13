// The IdP Worker's routes. This layer only reads the request into the core's input types and renders the core's
// decisions; every OIDC rule (validation order, redirects, codes, tokens) lives in src/domain.
import { Hono, type Context } from "hono";
import {
  authorize,
  buildDiscoveryDocument,
  buildJwks,
  endSession,
  exchangeToken,
  logout,
  resumeAuthorize,
  selectUiLocale,
  userinfo,
  type AuthorizeDecision,
  type Clock,
  type EndSessionDecision,
  type OidcDeps,
  type PasskeyDeps,
  type RandomSource,
} from "./domain/index.js";
import { isAcceptedTlsVersion } from "@idp/cloudflare/workers/tls";
import type { Issuer } from "@idp/issuer";
import { InvalidConfigError, workerConfig, type Env, type WorkerConfig } from "./config.js";
import { renderErrorPage } from "./error-page.js";
import { renderLogoutConfirmPage, renderLogoutErrorPage, renderSignedOutPage } from "./logout-page.js";
import { COOKIES, clearCookie, isSameOrigin, log, readCookie, readForm, writeCookie } from "./http.js";
import { mountWebauthnRoutes } from "./webauthn.js";

/** The Hono environment of every route: the Worker's bindings and the validated config. */
export type AppEnv = { Bindings: Env; Variables: { config: WorkerConfig } };

/** What the app takes besides the environment; the tests fix both, the Worker uses the system ones. */
export type AppOptions = {
  readonly clock: Clock;
  readonly random: RandomSource;
};

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

/** Seconds a limited client is told to wait: the binding's counting period (RATE_LIMIT in cloudflare.config.ts). */
const RATE_LIMIT_RETRY_AFTER_SECONDS = "10";

/**
 * Counts the request against the client IP's limit before any route runs (docs/design/free-tier.md). The count is
 * per Cloudflare location and approximate, a guard against simple floods on the pre-authentication D1 writes, not
 * an exact quota. The IP is only the counting key: it is never logged or stored (design principle 7).
 *
 * @param limiter The Rate Limiting binding.
 * @param clientIp The CF-Connecting-IP header, which Cloudflare's edge sets on every request.
 * @returns A refusal, or `undefined` when the request may proceed. Without an IP, or when the binding fails, the
 *   request is refused rather than let through uncounted (fail-closed).
 */
async function rateLimit(limiter: RateLimit, clientIp: string | undefined): Promise<Response | undefined> {
  if (clientIp === undefined || clientIp === "") {
    log({ result: "refused", reason: "no_client_ip" });
    return new Response("Bad request.", { status: 400 });
  }
  let outcome: RateLimitOutcome;
  try {
    outcome = await limiter.limit({ key: clientIp });
  } catch (error) {
    log({ result: "refused", reason: "rate_limiter_failed", error: describe(error) });
    return new Response("The identity provider is temporarily unavailable.", { status: 503 });
  }
  if (outcome.success) return undefined;
  log({ result: "refused", reason: "rate_limited" });
  return new Response("Too many requests.", { status: 429, headers: { "retry-after": RATE_LIMIT_RETRY_AFTER_SECONDS } });
}

/**
 * The refusal of the edge checks. Not `c.notFound()`: the app's not-found handler serves static assets, which a
 * refused request must never reach.
 */
function refused(): Response {
  return new Response("Not Found", { status: 404, headers: { "content-type": "text/plain; charset=UTF-8" } });
}

/**
 * The routes counted by the rate limit: every path the Worker itself answers. Static pages are not counted: they
 * write nothing, and one page load fetches several of them, which the provisional limit would refuse.
 */
const RATE_LIMITED_PATHS = [
  "/.well-known/openid-configuration",
  "/jwks",
  "/authorize",
  "/authorize/resume",
  "/token",
  "/userinfo",
  "/logout",
  "/end_session",
  "/end_session/confirm",
  "/webauthn/*",
] as const;

/**
 * Whether the request carries a cookie named like the IdP's own (`__Host-…`), whatever its value.
 *
 * Other cookies do not block the redirect: in a zone shared with the service, the service's non-Secure cookies for
 * the parent domain travel with every plain http request, and refusing them would turn every http visit into a 404.
 * A browser never sends a `__Host-` cookie over http (it requires Secure), so such a name on plain http means a
 * misbehaving client that may be replaying the IdP's session; it is refused like an Authorization header.
 *
 * @param request The plain http request.
 * @returns Whether any cookie name starts with `__Host-`.
 */
function carriesHostPrefixedCookie(request: Request): boolean {
  const header = request.headers.get("cookie");
  if (header === null) return false;
  return header.split(";").some((pair) => pair.trimStart().startsWith("__Host-"));
}

/**
 * Decides what a plain http request to the issuer host gets, now that no zone rule redirects it
 * (docs/design/domain-placement.md, 3).
 *
 * Only a safe method without credentials (no Authorization header, no `__Host-` cookie) is redirected, with 308 to the
 * configured issuer (never a host or port taken from the request) and the same path and query. Anything else is
 * refused without processing: a client secret, code, Bearer token, or session cookie sent over http is already exposed, and a redirect would invite the client to send it
 * again (RFC 9110 §15.4.9 keeps the method and body on a 308).
 *
 * @param request The plain http request.
 * @param url Its parsed URL.
 * @param issuer The configured issuer.
 * @returns The redirect, or `undefined` when the request must be refused.
 */
function plainHttpRedirect(request: Request, url: URL, issuer: Issuer): Response | undefined {
  if (request.method !== "GET" && request.method !== "HEAD") return undefined;
  if (request.headers.has("authorization") || carriesHostPrefixedCookie(request)) return undefined;
  return new Response(null, { status: 308, headers: { location: `${issuer.origin}${url.pathname}${url.search}` } });
}

/**
 * Builds the IdP Worker application.
 *
 * @param options The clock and the random source.
 * @returns The Hono app; every request passes the config and host checks before routing.
 */
export function createApp(options: AppOptions): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  function deps(c: Context<AppEnv>): OidcDeps {
    const { db, issuer, keys } = c.get("config");
    return { db, issuer, keys, clock: options.clock, random: options.random };
  }

  function passkeyDeps(c: Context<AppEnv>): PasskeyDeps {
    const { db, issuer, writerVersion } = c.get("config");
    return { db, issuer, writerVersion, clock: options.clock, random: options.random };
  }

  // Redirects use 302 for GET and 303 for POST, never 307, which would replay the form body to the RP
  // (standards-compliance.md).
  function redirect(c: Context<AppEnv>, location: string): Response {
    return c.redirect(location, c.req.method === "GET" ? 302 : 303);
  }

  function render(c: Context<AppEnv>, route: string, decision: AuthorizeDecision): Response {
    log({ route, decision: decision.kind, ...("error" in decision ? { error: decision.error } : {}) });
    switch (decision.kind) {
      case "error_page":
        return c.html(renderErrorPage(decision.error, decision.locale), 400);
      case "error_redirect":
      case "code_redirect":
        return redirect(c, decision.location);
      case "sign_in":
        writeCookie(c, COOKIES.authorizeRequest, decision.authorizeRequestId, decision.expiresAt - options.clock.now());
        // A 303 from GET too: the sign-in page is fetched with GET whatever brought the browser here.
        return c.redirect(`/signin?lang=${decision.locale}`, 303);
    }
  }

  app.use("*", async (c, next) => {
    let config: WorkerConfig;
    try {
      config = await workerConfig(c.env);
    } catch (error) {
      if (!(error instanceof InvalidConfigError)) throw error;
      log({ result: "refused", reason: "config", error: error.message });
      return c.text("The identity provider is misconfigured.", 500);
    }
    // The custom domain is the only route, but a request on any other host (a re-enabled workers.dev) is refused
    // rather than answered with endpoints derived from the configured issuer. The host is checked before the scheme,
    // so a redirect is only ever issued for the issuer host.
    const url = new URL(c.req.url);
    if (url.hostname !== config.issuer.rpId) {
      log({ result: "refused", reason: "host" });
      return refused();
    }
    // The Worker runs first on every request, the pages included, and no zone rule redirects plain http, so this is
    // the only place that does (docs/design/domain-placement.md, 3).
    if (url.protocol !== "https:") {
      const redirect = url.protocol === "http:" ? plainHttpRedirect(c.req.raw, url, config.issuer) : undefined;
      log({ result: redirect === undefined ? "refused" : "redirected", reason: "scheme" });
      return redirect ?? refused();
    }
    // The zone's minimum TLS version belongs to the zone's owner, so TLS below 1.2 is refused here like plain http,
    // for the pages too (docs/design/deployment.md, "設定値"; RFC 8996 exception recorded in
    // docs/design/domain-placement.md, 3).
    if (!isAcceptedTlsVersion(c.req.raw.cf)) {
      log({ result: "refused", reason: "tls" });
      return refused();
    }
    c.set("config", config);
    await next();
  });

  for (const path of RATE_LIMITED_PATHS) {
    app.use(path, async (c, next) => {
      const limited = await rateLimit(c.get("config").rateLimiter, c.req.header("cf-connecting-ip"));
      if (limited !== undefined) return limited;
      await next();
    });
  }

  app.get("/.well-known/openid-configuration", (c) => {
    const { issuer, keys } = c.get("config");
    return c.json(buildDiscoveryDocument(issuer, keys));
  });

  app.get("/jwks", (c) => c.json(buildJwks(c.get("config").keys)));

  app.on(["GET", "POST"], "/authorize", async (c) => {
    // A POST is read from its form body only; parameters in its query are ignored (OIDC Core §3.1.2.1).
    const params = c.req.method === "GET" ? [...new URL(c.req.url).searchParams] : ((await readForm(c.req.raw)) ?? []);
    const decision = await authorize(deps(c), {
      params,
      sessionToken: readCookie(c, COOKIES.session),
      acceptLanguage: c.req.header("accept-language"),
    });
    return render(c, "authorize", decision);
  });

  // The sign-in page submits a form here after /webauthn/auth/verify. POST only, behind the same-origin check: it
  // consumes the saved request and issues a code, so a cross-site page must not be able to trigger it.
  app.post("/authorize/resume", async (c) => {
    const acceptLanguage = c.req.header("accept-language");
    if (!isSameOrigin(c.req.raw, c.get("config").issuer)) {
      log({ route: "authorize_resume", result: "refused", reason: "origin" });
      return c.html(renderErrorPage("cross_origin_request", selectUiLocale(undefined, acceptLanguage)), 403);
    }
    const authorizeRequestId = readCookie(c, COOKIES.authorizeRequest);
    // The row is single-use and taken by the core whatever the outcome, so the cookie has no further use either.
    clearCookie(c, COOKIES.authorizeRequest);
    const decision = await resumeAuthorize(deps(c), {
      authorizeRequestId,
      sessionToken: readCookie(c, COOKIES.session),
      acceptLanguage,
    });
    return render(c, "authorize_resume", decision);
  });

  app.post("/token", async (c) => {
    const form = await readForm(c.req.raw);
    if (form === undefined) {
      log({ route: "token", status: 400, error: "invalid_request" });
      return c.json({ error: "invalid_request" }, 400, { pragma: "no-cache" });
    }
    const response = await exchangeToken(deps(c), { authorization: c.req.header("authorization"), params: form });
    log({ route: "token", status: response.status, ...("error" in response.body ? { error: response.body.error } : {}) });
    return c.json(response.body, response.status, response.headers);
  });

  app.on(["GET", "POST"], "/userinfo", async (c) => {
    const response = await userinfo(deps(c), { authorization: c.req.header("authorization") });
    log({ route: "userinfo", status: response.status });
    if (response.body === null) return c.body(null, response.status, response.headers);
    return c.json(response.body, response.status, response.headers);
  });

  app.post("/logout", async (c) => {
    if (!isSameOrigin(c.req.raw, c.get("config").issuer)) {
      log({ route: "logout", result: "refused", reason: "origin" });
      return c.body(null, 403);
    }
    await logout(deps(c), readCookie(c, COOKIES.session));
    clearCookie(c, COOKIES.session);
    log({ route: "logout", status: 204 });
    return c.body(null, 204);
  });

  // RP-Initiated Logout 1.0 (authentication.md, "RP からのログアウト"). Kept apart from POST /logout, the account
  // page's same-origin API, because an RP's cross-site GET or form POST is a legitimate request here.
  function renderEndSession(c: Context<AppEnv>, route: string, decision: EndSessionDecision): Response {
    log({ route, decision: decision.kind, ...("error" in decision ? { error: decision.error } : {}) });
    switch (decision.kind) {
      case "error_page":
        return c.html(renderLogoutErrorPage(decision.error, decision.locale), 400);
      case "confirm":
        return c.html(renderLogoutConfirmPage(decision.locale, decision.form, decision.otherUser), 200);
      case "redirect":
        clearCookie(c, COOKIES.session);
        return redirect(c, decision.location);
      case "signed_out":
        clearCookie(c, COOKIES.session);
        return c.html(renderSignedOutPage(decision.locale), 200);
    }
  }

  async function endSessionParams(c: Context<AppEnv>): Promise<readonly (readonly [string, string])[] | undefined> {
    // A POST is read from its form body only, as at /authorize; parameters in its query are ignored.
    return c.req.method === "GET" ? [...new URL(c.req.url).searchParams] : readForm(c.req.raw);
  }

  app.on(["GET", "POST"], "/end_session", async (c) => {
    const params = await endSessionParams(c);
    if (params === undefined) {
      return renderEndSession(c, "end_session", {
        kind: "error_page",
        error: "invalid_request",
        locale: selectUiLocale(undefined, c.req.header("accept-language")),
      });
    }
    const decision = await endSession(deps(c), {
      params,
      sessionToken: readCookie(c, COOKIES.session),
      acceptLanguage: c.req.header("accept-language"),
      via: c.req.method === "GET" ? "get" : "post",
    });
    return renderEndSession(c, "end_session", decision);
  });

  // The confirmation page posts here. Behind the same-origin check, so only the IdP's own page completes a logout
  // that was not proven to come from the current session; the carried values are validated again by the core.
  app.post("/end_session/confirm", async (c) => {
    const acceptLanguage = c.req.header("accept-language");
    if (!isSameOrigin(c.req.raw, c.get("config").issuer)) {
      log({ route: "end_session_confirm", result: "refused", reason: "origin" });
      return c.html(renderLogoutErrorPage("cross_origin_request", selectUiLocale(undefined, acceptLanguage)), 403);
    }
    const params = await endSessionParams(c);
    if (params === undefined) {
      return renderEndSession(c, "end_session_confirm", { kind: "error_page", error: "invalid_request", locale: selectUiLocale(undefined, acceptLanguage) });
    }
    const decision = await endSession(deps(c), { params, sessionToken: readCookie(c, COOKIES.session), acceptLanguage, via: "confirmation" });
    return renderEndSession(c, "end_session_confirm", decision);
  });

  mountWebauthnRoutes(app, passkeyDeps, options.clock);

  // Whatever no route answers is a static page, fetched only with a safe method; the asset server answers 404 for a
  // path it does not have (notFoundHandling "none").
  app.notFound((c) => {
    if (c.req.method !== "GET" && c.req.method !== "HEAD") return c.text("Not Found", 404);
    return c.get("config").assets.fetch(c.req.raw);
  });
  app.onError((error, c) => {
    log({ result: "error", error: describe(error) });
    return c.text("Internal Server Error", 500);
  });
  return app;
}
