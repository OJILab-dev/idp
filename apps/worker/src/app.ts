// The IdP Worker's routes. This layer only reads the request into the core's input types and renders the core's
// decisions; every OIDC rule (validation order, redirects, codes, tokens) lives in @idp/core/user.
import { Hono, type Context } from "hono";
import {
  authorize,
  buildDiscoveryDocument,
  buildJwks,
  exchangeToken,
  logout,
  resumeAuthorize,
  selectUiLocale,
  userinfo,
  type AuthorizeDecision,
  type Clock,
  type OidcDeps,
  type RandomSource,
} from "@idp/core/user";
import { InvalidConfigError, workerConfig, type Env, type WorkerConfig } from "./config.js";
import { renderErrorPage } from "./error-page.js";
import { COOKIES, clearCookie, isSameOrigin, log, readCookie, readForm, writeCookie } from "./http.js";

type AppEnv = { Bindings: Env; Variables: { config: WorkerConfig } };

/** What the app takes besides the environment; the tests fix both, the Worker uses the system ones. */
export type AppOptions = {
  readonly clock: Clock;
  readonly random: RandomSource;
};

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
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
    // rather than answered with endpoints derived from the configured issuer.
    if (new URL(c.req.url).hostname !== config.issuer.rpId) {
      log({ result: "refused", reason: "host" });
      return c.notFound();
    }
    c.set("config", config);
    await next();
  });

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

  // The /webauthn/* routes (sign-in, enrollment, and the account page's API) are mounted here by the passkey PR;
  // until then they fall through to the 404 below.

  app.notFound((c) => c.text("Not Found", 404));
  app.onError((error, c) => {
    log({ result: "error", error: describe(error) });
    return c.text("Internal Server Error", 500);
  });
  return app;
}
