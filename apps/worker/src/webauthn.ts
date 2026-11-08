// The /webauthn/* API the three pages call (docs/design/authentication.md): the passkey sign-in, the enrollment
// through an enroll link, and the account page's list, add, and revoke. Each route reads the request into one core
// use case and maps its typed result to JSON; every WebAuthn rule lives in @idp/core/user.
import type { Context, Hono } from "hono";
import {
  addBegin,
  addOptions,
  addVerify,
  enrollOptions,
  enrollVerify,
  listOwnPasskeys,
  revokeBegin,
  revokeVerify,
  signInOptions,
  signInVerify,
  type Clock,
  type PasskeyDeps,
  type PasskeyRejection,
  type PasskeyRejectionReason,
} from "@idp/core/user";
import { COOKIES, clearCookie, isSameOrigin, isSameOriginFetch, log, readCookie, readJsonObject, writeCookie } from "./http.js";
import type { AppEnv } from "./app.js";

/** The error kinds a page can receive. Each names what the user can do next, never which check failed. */
type ErrorKind = "invalid_request" | "no_session" | "cross_origin_request" | "passkey_rejected" | "limit_reached" | "last_passkey";

type Refusal = { readonly status: 400 | 401 | 403 | 409; readonly error: ErrorKind };

const REJECTED: Refusal = { status: 403, error: "passkey_rejected" };

// Only the outcomes the user can act on differently stay distinct: sign in from the app (no_session), remove a
// passkey first (limit_reached), or add one first (last_passkey). Every failed check (challenge, token, authorize
// request, signature, credential ownership, a disabled user, a duplicate credential) is the same passkey_rejected,
// so the response never tells a prober which check it failed; the log line keeps the core's reason.
const REFUSALS: Readonly<Record<PasskeyRejectionReason, Refusal>> = {
  invalid_request: { status: 400, error: "invalid_request" },
  no_session: { status: 401, error: "no_session" },
  invalid_authorize_request: REJECTED,
  invalid_enroll_token: REJECTED,
  invalid_challenge: REJECTED,
  unknown_credential: REJECTED,
  verification_failed: REJECTED,
  user_disabled: REJECTED,
  credential_exists: REJECTED,
  limit_reached: { status: 409, error: "limit_reached" },
  last_passkey: { status: 409, error: "last_passkey" },
};

type Body = Readonly<Record<string, unknown>>;

const INVALID_REQUEST: PasskeyRejection = { kind: "rejected", reason: "invalid_request" };

function refuse(c: Context<AppEnv>, route: string, rejection: PasskeyRejection): Response {
  const { status, error } = REFUSALS[rejection.reason];
  log({ route, status, reason: rejection.reason });
  return c.json({ error }, status);
}

function succeed(c: Context<AppEnv>, route: string, body: unknown): Response {
  log({ route, status: 200 });
  return c.json(body, 200);
}

function text(body: Body, name: string): string | undefined {
  const value = body[name];
  return typeof value === "string" ? value : undefined;
}

/**
 * Mounts the /webauthn/* routes.
 *
 * Every route is behind the same-origin check: the POSTs change state with the browser's cookies, and the GET
 * returns the session user's passkeys, which a cross-site top-level navigation must not read either.
 *
 * @param app The IdP Worker's app, after the config and host checks.
 * @param deps The passkey dependencies of a request.
 * @param clock The clock the cookies' Max-Age is computed with; the same one the core stores expiries with.
 */
export function mountWebauthnRoutes(app: Hono<AppEnv>, deps: (c: Context<AppEnv>) => PasskeyDeps, clock: Clock): void {
  app.use("/webauthn/*", async (c, next) => {
    const allowed = c.req.method === "GET" ? isSameOriginFetch(c.req.raw) : isSameOrigin(c.req.raw, c.get("config").issuer);
    if (!allowed) {
      log({ route: "webauthn", result: "refused", reason: "origin" });
      return c.json({ error: "cross_origin_request" satisfies ErrorKind }, 403);
    }
    await next();
  });

  // Routes that take a JSON body: a missing or malformed one is refused before the core is called.
  function withBody(path: string, route: string, handle: (c: Context<AppEnv>, body: Body) => Promise<Response>): void {
    app.post(path, async (c) => {
      const body = await readJsonObject(c.req.raw);
      return body === undefined ? refuse(c, route, INVALID_REQUEST) : handle(c, body);
    });
  }

  function session(c: Context<AppEnv>): string | undefined {
    return readCookie(c, COOKIES.session);
  }

  app.post("/webauthn/auth/options", async (c) => {
    const result = await signInOptions(deps(c), { authorizeRequestId: readCookie(c, COOKIES.authorizeRequest) });
    return result.kind === "options" ? succeed(c, "auth_options", result.options) : refuse(c, "auth_options", result);
  });

  withBody("/webauthn/auth/verify", "auth_verify", async (c, body) => {
    const result = await signInVerify(deps(c), {
      authorizeRequestId: readCookie(c, COOKIES.authorizeRequest),
      sessionToken: session(c),
      credential: body["credential"],
    });
    if (result.kind === "rejected") return refuse(c, "auth_verify", result);
    // The authorize request cookie stays: the page posts /authorize/resume next, which consumes it.
    writeCookie(c, COOKIES.session, result.sessionToken, result.expiresAt - clock.now());
    log({ route: "auth_verify", status: 204 });
    return c.body(null, 204);
  });

  withBody("/webauthn/register/options", "register_options", async (c, body) => {
    const enrollToken = text(body, "token");
    if (enrollToken === undefined) return refuse(c, "register_options", INVALID_REQUEST);
    const result = await enrollOptions(deps(c), { enrollToken });
    return result.kind === "options" ? succeed(c, "register_options", result.options) : refuse(c, "register_options", result);
  });

  withBody("/webauthn/register/verify", "register_verify", async (c, body) => {
    const enrollToken = text(body, "token");
    if (enrollToken === undefined) return refuse(c, "register_verify", INVALID_REQUEST);
    const result = await enrollVerify(deps(c), { enrollToken, credential: body["credential"] });
    return result.kind === "registered"
      ? succeed(c, "register_verify", { credential_id: result.credentialId })
      : refuse(c, "register_verify", result);
  });

  app.get("/webauthn/credentials", async (c) => {
    const result = await listOwnPasskeys(deps(c), { sessionToken: session(c) });
    return result.kind === "passkeys" ? succeed(c, "credentials", { credentials: result.passkeys }) : refuse(c, "credentials", result);
  });

  app.post("/webauthn/add/begin", async (c) => {
    const result = await addBegin(deps(c), { sessionToken: session(c) });
    return result.kind === "options" ? succeed(c, "add_begin", result.options) : refuse(c, "add_begin", result);
  });

  withBody("/webauthn/add/options", "add_options", async (c, body) => {
    const result = await addOptions(deps(c), { sessionToken: session(c), credential: body["credential"] });
    return result.kind === "options" ? succeed(c, "add_options", result.options) : refuse(c, "add_options", result);
  });

  withBody("/webauthn/add/verify", "add_verify", async (c, body) => {
    const result = await addVerify(deps(c), { sessionToken: session(c), credential: body["credential"] });
    return result.kind === "registered" ? succeed(c, "add_verify", { credential_id: result.credentialId }) : refuse(c, "add_verify", result);
  });

  withBody("/webauthn/revoke/begin", "revoke_begin", async (c, body) => {
    const credentialId = text(body, "credential_id");
    if (credentialId === undefined) return refuse(c, "revoke_begin", INVALID_REQUEST);
    const result = await revokeBegin(deps(c), { sessionToken: session(c), credentialId });
    return result.kind === "options" ? succeed(c, "revoke_begin", result.options) : refuse(c, "revoke_begin", result);
  });

  withBody("/webauthn/revoke/verify", "revoke_verify", async (c, body) => {
    const credentialId = text(body, "credential_id");
    if (credentialId === undefined) return refuse(c, "revoke_verify", INVALID_REQUEST);
    const result = await revokeVerify(deps(c), { sessionToken: session(c), credentialId, credential: body["credential"] });
    if (result.kind === "rejected") return refuse(c, "revoke_verify", result);
    // The session row went with the passkey it was signed in with (ON DELETE CASCADE); the cookie follows it.
    if (result.sessionEnded) clearCookie(c, COOKIES.session);
    return succeed(c, "revoke_verify", { session_ended: result.sessionEnded });
  });
}
