// The authorization endpoint (docs/design/authentication.md, sign-in steps 1 to 4 and 6). The order of the checks is
// the security property: until client_id and redirect_uri are validated nothing is redirected anywhere (RFC 6749
// §4.1.2.1), and after that every error goes to the validated redirect_uri with iss and state (RFC 9207, RFC 6749
// §4.1.2.1). The HTTP layer only renders the returned decision.
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isRegisteredRedirectUri } from "@idp/oauth-native-apps";
import { isS256CodeChallenge } from "@idp/pkce";
import { isClientId, isRandomTokenFormat } from "../identifiers/index.js";
import type { Issuer } from "../issuer/index.js";
import type { SqlRow } from "../db/index.js";
import { CorruptRowError, loadClient, type RegisteredClient } from "./clients.js";
import type { OidcDeps } from "./deps.js";
import { asUiLocale, selectUiLocale, type UiLocale } from "./locale.js";
import { findActiveSession, hasAccess, type ActiveSession } from "./sessions.js";
import { InvalidTokenError, verifyIdTokenHint, type GrantedScope } from "./tokens.js";

/** How long a saved authorize request lives: the 10-minute challenge plus time to load the page. */
export const AUTHORIZE_REQUEST_LIFETIME_SECONDS = 900;

/** How long an authorization code lives (RFC 6749 §4.1.2 recommends at most 10 minutes). */
export const AUTH_CODE_LIFETIME_SECONDS = 60;

// state and nonce are stored in D1 and echoed back; a bound keeps one request from writing an arbitrarily large row.
const MAX_STORED_PARAMETER_LENGTH = 2048;

const MAX_AGE = /^(?:0|[1-9][0-9]{0,9})$/;

/** A request to `/authorize`, from the query (GET) or the form body (POST). */
export type AuthorizeInput = {
  /** The parameters in the order received; a name may repeat, which is itself an error (RFC 6749 §3.1). */
  readonly params: readonly (readonly [string, string])[];
  /** The session cookie's value; `undefined` when absent. */
  readonly sessionToken: string | undefined;
  /** The `Accept-Language` header; `undefined` when absent. */
  readonly acceptLanguage: string | undefined;
};

/** A request to `/authorize/resume` after the passkey sign-in. */
export type ResumeInput = {
  /** The authorize request cookie's value; `undefined` when absent. */
  readonly authorizeRequestId: string | undefined;
  readonly sessionToken: string | undefined;
  readonly acceptLanguage: string | undefined;
};

/**
 * Why the endpoint shows an error page instead of redirecting. `unsupported_response_mode` is a 400 without error
 * parameters (docs/design/standards-compliance.md); the others mean the redirect target could not be trusted.
 */
export type AuthorizeErrorPageReason =
  | "invalid_client"
  | "invalid_redirect_uri"
  | "unsupported_response_mode"
  | "invalid_authorize_request";

/** The `error` values sent to a validated redirect_uri (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6 and §6.2). */
export type AuthorizeRedirectError =
  | "invalid_request"
  | "unsupported_response_type"
  | "invalid_scope"
  | "access_denied"
  | "login_required"
  | "server_error"
  | "request_not_supported"
  | "request_uri_not_supported"
  | "registration_not_supported";

/** What the endpoint does. Redirects use 302 or 303, never 307 (docs/design/standards-compliance.md). */
export type AuthorizeDecision =
  | { readonly kind: "error_page"; readonly error: AuthorizeErrorPageReason; readonly locale: UiLocale }
  | { readonly kind: "error_redirect"; readonly error: AuthorizeRedirectError; readonly location: string }
  | {
      readonly kind: "sign_in";
      /** The plaintext ID for the `__Host-` cookie; only its hash is stored. */
      readonly authorizeRequestId: string;
      /** Passed to the sign-in page as `/signin?lang=<locale>`. */
      readonly locale: UiLocale;
      /** When the saved request expires, in UNIX seconds; the cookie should not outlive it. */
      readonly expiresAt: number;
    }
  | { readonly kind: "code_redirect"; readonly location: string };

// A request whose every parameter has been checked; what authorize_requests stores.
type ValidatedRequest = {
  readonly client: RegisteredClient;
  readonly redirectUri: string;
  readonly state: string | undefined;
  readonly nonce: string | undefined;
  readonly codeChallenge: string;
  readonly scope: string;
  readonly promptNone: boolean;
  /** prompt=login, prompt=select_account, or max_age=0: a fresh passkey sign-in is required. */
  readonly promptLogin: boolean;
  readonly maxAge: number | undefined;
  readonly idTokenHintSub: string | undefined;
  readonly locale: UiLocale;
};

type Params = ReadonlyMap<string, readonly string[]>;

/**
 * Handles `/authorize` (GET and POST).
 *
 * @param deps The database, issuer, keys, clock, and random source.
 * @param input The request parameters and cookies.
 * @returns The decision: an error page; an error redirect with `error`, `iss`, and `state`; the sign-in page with a
 *   saved authorize request; or a code redirect with `code`, `iss`, and `state`.
 * @throws {CorruptRowError} The client or session row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function authorize(deps: OidcDeps, input: AuthorizeInput): Promise<AuthorizeDecision> {
  const params = collectParams(input.params);
  const locale = selectUiLocale(first(params, "ui_locales"), input.acceptLanguage);
  const validated = await validateRequest(deps, params, locale);
  if (validated.kind !== "valid") return validated.decision;
  const request = validated.request;

  let session = await findActiveSession(deps, input.sessionToken);
  // OIDC Core §3.1.2.1: a hint naming someone else means this session cannot answer the request.
  if (session !== undefined && request.idTokenHintSub !== undefined && session.userId !== request.idTokenHintSub) {
    if (request.promptNone) return errorRedirect(deps.issuer, request, "login_required");
    session = undefined;
  }
  if (session === undefined || needsReauthentication(deps, request, session)) {
    if (request.promptNone) return errorRedirect(deps.issuer, request, "login_required");
    return saveAuthorizeRequest(deps, request);
  }
  return issueCodeOrDeny(deps, request, session);
}

/**
 * Handles `/authorize/resume`: takes the saved request exactly once and, if the new session satisfies it, issues a code.
 *
 * @param deps The database, issuer, keys, clock, and random source.
 * @param input The authorize request cookie and the session cookie.
 * @returns An error page when the saved request is missing or expired or its client or redirect_uri is no longer
 *   valid; otherwise an error redirect or a code redirect.
 * @throws {CorruptRowError} The saved request, client, or session row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function resumeAuthorize(deps: OidcDeps, input: ResumeInput): Promise<AuthorizeDecision> {
  const fallbackLocale = selectUiLocale(undefined, input.acceptLanguage);
  if (input.authorizeRequestId === undefined || !isRandomTokenFormat(input.authorizeRequestId)) {
    return errorPage("invalid_authorize_request", fallbackLocale);
  }
  // Deleted whether or not it is still valid: the row is single-use, and an expired row has no further use.
  const [taken] = await deps.db.batch([
    {
      sql: "DELETE FROM authorize_requests WHERE id_hash = ? RETURNING *",
      params: [await sha256Base64url(input.authorizeRequestId)],
    },
  ]);
  const row = taken?.rows[0];
  if (row === undefined) return errorPage("invalid_authorize_request", fallbackLocale);
  const saved = parseSavedRequest(row);
  if (saved.expiresAt <= deps.clock.now()) return errorPage("invalid_authorize_request", saved.locale);

  // The client and its registration may have changed during the sign-in; validate them again from scratch.
  const client = await loadClient(deps.db, saved.clientId);
  if (client === undefined || !client.enabled) return errorPage("invalid_client", saved.locale);
  if (!isRegisteredRedirectUri(client.redirectUris, saved.redirectUri)) return errorPage("invalid_redirect_uri", saved.locale);
  const request: ValidatedRequest = { ...saved, client, promptNone: false };
  if (signingUnavailable(deps, client)) return errorRedirect(deps.issuer, request, "server_error");

  const session = await findActiveSession(deps, input.sessionToken);
  if (session === undefined) return errorRedirect(deps.issuer, request, "login_required");
  const mustBeFresh = request.promptLogin || client.clientType === "public";
  if (mustBeFresh && session.authTime < saved.createdAt) return errorRedirect(deps.issuer, request, "login_required");
  if (maxAgeExceeded(deps, request, session)) return errorRedirect(deps.issuer, request, "login_required");
  if (request.idTokenHintSub !== undefined && session.userId !== request.idTokenHintSub) {
    return errorRedirect(deps.issuer, request, "login_required");
  }
  return issueCodeOrDeny(deps, request, session);
}

type Validation =
  | { readonly kind: "valid"; readonly request: ValidatedRequest }
  | { readonly kind: "rejected"; readonly decision: AuthorizeDecision };

async function validateRequest(deps: OidcDeps, params: Params, locale: UiLocale): Promise<Validation> {
  function reject(decision: AuthorizeDecision): Validation {
    return { kind: "rejected", decision };
  }

  const clientId = single(params, "client_id");
  if (clientId === undefined || !isClientId(clientId)) return reject(errorPage("invalid_client", locale));
  const client = await loadClient(deps.db, clientId);
  // A disabled client's redirect URIs may no longer belong to the RP, so even a matching one is not used.
  if (client === undefined || !client.enabled) return reject(errorPage("invalid_client", locale));
  const redirectUri = single(params, "redirect_uri");
  if (redirectUri === undefined || !isRegisteredRedirectUri(client.redirectUris, redirectUri)) {
    return reject(errorPage("invalid_redirect_uri", locale));
  }

  const responseMode = first(params, "response_mode");
  if (responseMode !== undefined && responseMode !== "query") return reject(errorPage("unsupported_response_mode", locale));

  const validatedRedirectUri = redirectUri;
  const state = single(params, "state");
  function fail(error: AuthorizeRedirectError): Validation {
    return reject(errorRedirect(deps.issuer, { redirectUri: validatedRedirectUri, state }, error));
  }

  if ([...params.values()].some((values) => values.length > 1)) return fail("invalid_request");
  if (params.has("request")) return fail("request_not_supported");
  if (params.has("request_uri")) return fail("request_uri_not_supported");
  if (params.has("registration")) return fail("registration_not_supported");

  const responseType = single(params, "response_type");
  if (responseType === undefined) return fail("invalid_request");
  if (responseType !== "code") return fail("unsupported_response_type");

  const requestedScopes = single(params, "scope")?.split(" ") ?? [];
  if (!requestedScopes.includes("openid")) return fail("invalid_scope");
  // Everything but profile (email included) is ignored, and the token response reports the granted scope.
  const scopes: readonly GrantedScope[] = requestedScopes.includes("profile") ? ["openid", "profile"] : ["openid"];

  // S256 only; an absent method means plain (RFC 7636 §4.3), which is rejected like an explicit one.
  const codeChallenge = single(params, "code_challenge");
  if (codeChallenge === undefined || !isS256CodeChallenge(codeChallenge)) return fail("invalid_request");
  if (single(params, "code_challenge_method") !== "S256") return fail("invalid_request");

  const prompt = parsePrompt(single(params, "prompt"));
  if (prompt === undefined) return fail("invalid_request");

  const maxAgeValue = single(params, "max_age");
  if (maxAgeValue !== undefined && !MAX_AGE.test(maxAgeValue)) return fail("invalid_request");
  const maxAge = maxAgeValue === undefined ? undefined : Number(maxAgeValue);

  const nonce = single(params, "nonce");
  if ((nonce?.length ?? 0) > MAX_STORED_PARAMETER_LENGTH || (state?.length ?? 0) > MAX_STORED_PARAMETER_LENGTH) {
    return fail("invalid_request");
  }

  let idTokenHintSub: string | undefined;
  const hint = single(params, "id_token_hint");
  if (hint !== undefined) {
    try {
      idTokenHintSub = (await verifyIdTokenHint(hint, deps)).sub;
    } catch (error) {
      if (error instanceof InvalidTokenError) return fail("invalid_request");
      throw error;
    }
  }

  // tokens.md: an RS256 client with no RSA key fails before the sign-in, not after the user has done it.
  if (signingUnavailable(deps, client)) return fail("server_error");

  return {
    kind: "valid",
    request: {
      client,
      redirectUri,
      state,
      nonce,
      codeChallenge,
      scope: scopes.join(" "),
      promptNone: prompt.none,
      promptLogin: prompt.login || maxAge === 0,
      maxAge,
      idTokenHintSub,
      locale,
    },
  };
}

// OIDC Core §3.1.2.1. select_account is met by the passkey picker, so it forces a sign-in like login. consent is
// accepted and ignored: access is the administrator's grant, and there is no per-user consent to ask for.
function parsePrompt(value: string | undefined): { readonly none: boolean; readonly login: boolean } | undefined {
  if (value === undefined) return { none: false, login: false };
  const values = value.split(" ");
  if (!values.every((v) => v === "none" || v === "login" || v === "consent" || v === "select_account")) return undefined;
  const none = values.includes("none");
  if (none && values.length > 1) return undefined;
  return { none, login: values.includes("login") || values.includes("select_account") };
}

function needsReauthentication(deps: OidcDeps, request: ValidatedRequest, session: ActiveSession): boolean {
  // RFC 8252 §8.6: anyone can claim a public client's ID, so its requests never ride on an existing session.
  return request.promptLogin || request.client.clientType === "public" || maxAgeExceeded(deps, request, session);
}

function maxAgeExceeded(deps: OidcDeps, request: Pick<ValidatedRequest, "maxAge">, session: ActiveSession): boolean {
  return request.maxAge !== undefined && deps.clock.now() - session.authTime > request.maxAge;
}

function signingUnavailable(deps: OidcDeps, client: RegisteredClient): boolean {
  return client.idTokenAlg === "RS256" && deps.keys.rsa === undefined;
}

async function saveAuthorizeRequest(deps: OidcDeps, request: ValidatedRequest): Promise<AuthorizeDecision> {
  const now = deps.clock.now();
  const id = deps.random.token();
  const expiresAt = now + AUTHORIZE_REQUEST_LIFETIME_SECONDS;
  await deps.db.batch([
    { sql: "DELETE FROM authorize_requests WHERE expires_at <= ?", params: [now] },
    {
      sql: `INSERT INTO authorize_requests (id_hash, client_id, redirect_uri, state, nonce, code_challenge, scope,
                                            prompt_login, max_age, id_token_hint_sub, locale, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [
        await sha256Base64url(id),
        request.client.id,
        request.redirectUri,
        request.state ?? null,
        request.nonce ?? null,
        request.codeChallenge,
        request.scope,
        request.promptLogin ? 1 : 0,
        request.maxAge ?? null,
        request.idTokenHintSub ?? null,
        request.locale,
        now,
        expiresAt,
      ],
    },
  ]);
  return { kind: "sign_in", authorizeRequestId: id, locale: request.locale, expiresAt };
}

async function issueCodeOrDeny(deps: OidcDeps, request: ValidatedRequest, session: ActiveSession): Promise<AuthorizeDecision> {
  if (!(await hasAccess(deps.db, session.userId, request.client.id))) {
    return errorRedirect(deps.issuer, request, "access_denied");
  }
  const now = deps.clock.now();
  const code = deps.random.token();
  // The insert repeats the session and access checks in the same statement, so a sign-out, revocation, or grant
  // removal between the read above and this write cannot leave a code behind.
  const [, inserted] = await deps.db.batch([
    { sql: "DELETE FROM auth_codes WHERE expires_at <= ?", params: [now] },
    {
      sql: `INSERT INTO auth_codes (code_hash, client_id, user_id, session_token_hash, redirect_uri, code_challenge,
                                    nonce, scope, auth_time, expires_at)
            SELECT ?, ?, s.user_id, s.token_hash, ?, ?, ?, ?, s.auth_time, ?
            FROM sessions s
            WHERE s.token_hash = ? AND s.expires_at > ?
              AND EXISTS (SELECT 1 FROM effective_access ea WHERE ea.user_id = s.user_id AND ea.client_id = ?)`,
      params: [
        await sha256Base64url(code),
        request.client.id,
        request.redirectUri,
        request.codeChallenge,
        request.nonce ?? null,
        request.scope,
        now + AUTH_CODE_LIFETIME_SECONDS,
        session.tokenHash,
        now,
        request.client.id,
      ],
    },
  ]);
  if (inserted?.changes !== 1) return errorRedirect(deps.issuer, request, "access_denied");
  return { kind: "code_redirect", location: redirectLocation(request.redirectUri, { code, state: request.state, iss: deps.issuer.url }) };
}

function errorPage(error: AuthorizeErrorPageReason, locale: UiLocale): AuthorizeDecision {
  return { kind: "error_page", error, locale };
}

function errorRedirect(
  issuer: Issuer,
  target: Pick<ValidatedRequest, "redirectUri" | "state">,
  error: AuthorizeRedirectError,
): AuthorizeDecision {
  return {
    kind: "error_redirect",
    error,
    location: redirectLocation(target.redirectUri, { error, state: target.state, iss: issuer.url }),
  };
}

/**
 * Appends parameters to a registered URI's own query, which RFC 6749 §3.1.2 requires the server to keep. The
 * post-logout redirect (end-session.ts) keeps it the same way.
 *
 * @param redirectUri A registered, validated URI.
 * @param params The parameters to append; an `undefined` value is left out.
 * @returns The URI to redirect to.
 */
export function redirectLocation(redirectUri: string, params: Readonly<Record<string, string | undefined>>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.append(name, value);
  }
  return url.href;
}

// RFC 6749 §3.1: a parameter sent without a value is treated as omitted.
function collectParams(pairs: AuthorizeInput["params"]): Params {
  const params = new Map<string, string[]>();
  for (const [name, value] of pairs) {
    if (value === "") continue;
    const values = params.get(name);
    if (values === undefined) params.set(name, [value]);
    else values.push(value);
  }
  return params;
}

// The value when the parameter appears exactly once; a repeated client_id or redirect_uri is as untrusted as a
// missing one, and any other repeat is rejected before the value is used.
function single(params: Params, name: string): string | undefined {
  const values = params.get(name);
  return values?.length === 1 ? values[0] : undefined;
}

function first(params: Params, name: string): string | undefined {
  return params.get(name)?.[0];
}

type SavedRequest = Omit<ValidatedRequest, "client" | "promptNone"> & {
  readonly clientId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
};

function parseSavedRequest(row: SqlRow): SavedRequest {
  function text(name: string): string {
    const value = row[name];
    if (typeof value !== "string") throw new CorruptRowError(`authorize_requests.${name} is malformed`);
    return value;
  }
  function optionalText(name: string): string | undefined {
    return row[name] === null ? undefined : text(name);
  }
  function integer(name: string): number {
    const value = row[name];
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new CorruptRowError(`authorize_requests.${name} is malformed`);
    }
    return value;
  }
  const locale = asUiLocale(row["locale"]);
  if (locale === undefined) throw new CorruptRowError("authorize_requests.locale is malformed");
  return {
    clientId: text("client_id"),
    redirectUri: text("redirect_uri"),
    state: optionalText("state"),
    nonce: optionalText("nonce"),
    codeChallenge: text("code_challenge"),
    scope: text("scope"),
    promptLogin: integer("prompt_login") === 1,
    maxAge: row["max_age"] === null ? undefined : integer("max_age"),
    idTokenHintSub: optionalText("id_token_hint_sub"),
    locale,
    createdAt: integer("created_at"),
    expiresAt: integer("expires_at"),
  };
}
