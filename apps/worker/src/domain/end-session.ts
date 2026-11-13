// OpenID Connect RP-Initiated Logout 1.0 (docs/design/authentication.md, "RP からのログアウト"). The order is the
// security property: every parameter is validated before anything is used (§4), the session ends without asking only
// for a hint from the current session (§2, §6), and a redirect goes only to a URI the client registered (§3). The HTTP
// layer only renders the returned decision.
import { isClientId } from "@idp/identifiers";
import { redirectLocation } from "./authorize.js";
import { loadLogoutClient } from "./clients.js";
import type { OidcDeps } from "./deps.js";
import { selectUiLocale, type UiLocale } from "./locale.js";
import { findActiveSession, logout, type ActiveSession } from "./sessions.js";
import { InvalidTokenError, verifyLogoutIdTokenHint, type LogoutIdTokenHint } from "./tokens.js";

// Echoed back in the redirect and in the confirmation form; the same bound as the authorization request's state.
const MAX_STATE_LENGTH = 2048;

// The parameters of §2. A repeat of any of them is an error; unknown parameters are ignored, as in OAuth.
const LOGOUT_PARAMETERS = ["id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales"] as const;

type LogoutParameter = (typeof LOGOUT_PARAMETERS)[number];

/** How a logout request reached the IdP. */
export type EndSessionVia =
  /** `GET /end_session`: a top-level navigation carries the SameSite=Lax session cookie. */
  | "get"
  /** `POST /end_session`: a cross-site form POST carries no SameSite=Lax cookie, so a missing cookie proves nothing. */
  | "post"
  /** `POST /end_session/confirm`: the End-User confirmed on the IdP's own page (same-origin, checked by the caller). */
  | "confirmation";

/** A request to the logout endpoint or its confirmation. */
export type EndSessionInput = {
  /** The parameters in the order received: the query of a GET, the form body of a POST. */
  readonly params: readonly (readonly [string, string])[];
  /** The session cookie's value; `undefined` when absent. */
  readonly sessionToken: string | undefined;
  /** The `Accept-Language` header; `undefined` when absent. */
  readonly acceptLanguage: string | undefined;
  readonly via: EndSessionVia;
};

/** Why the logout request is refused; shown on the error page for support. */
export type EndSessionErrorReason = "invalid_request" | "invalid_id_token_hint" | "invalid_client" | "client_id_mismatch";

/** What the endpoint does. */
export type EndSessionDecision =
  /** The request is malformed: nothing is ended and nothing is redirected (§4). */
  | { readonly kind: "error_page"; readonly error: EndSessionErrorReason; readonly locale: UiLocale }
  /** The End-User must confirm (§2): the page posts `form` to `/end_session/confirm`. Nothing has been ended. */
  | {
      readonly kind: "confirm";
      readonly locale: UiLocale;
      /** The validated values to carry, re-validated on confirmation; every value must be HTML-escaped. */
      readonly form: readonly (readonly [string, string])[];
      /** The hint names another user than the current session's (§2: the request is suspect). */
      readonly otherUser: boolean;
    }
  /** The session (if any) has ended; redirect to the registered post-logout redirect URI with `state` (§3). */
  | { readonly kind: "redirect"; readonly location: string; readonly sessionEnded: boolean }
  /** The session (if any) has ended; show the IdP's own signed-out page. */
  | { readonly kind: "signed_out"; readonly locale: UiLocale; readonly sessionEnded: boolean };

// A request whose every parameter has been checked.
type ValidatedLogout = {
  readonly locale: UiLocale;
  readonly hintToken: string | undefined;
  readonly hint: LogoutIdTokenHint | undefined;
  readonly clientIdParam: string | undefined;
  /** The registered URI to return to, with the state to append; `undefined` when there is no valid redirect. */
  readonly redirect: { readonly uri: string; readonly state: string | undefined } | undefined;
};

/**
 * Handles `/end_session` (GET and POST) and its confirmation.
 *
 * @param deps The database, issuer, keys, and clock.
 * @param input The request parameters, the session cookie, and how the request arrived.
 * @returns The decision: an error page (nothing done), a confirmation page (nothing done), or, once the current
 *   session is deleted, a redirect to the registered post-logout redirect URI or the signed-out page.
 * @throws {CorruptRowError} The client or session row is malformed.
 * @throws {DatabaseError} A read or the delete failed.
 */
export async function endSession(deps: OidcDeps, input: EndSessionInput): Promise<EndSessionDecision> {
  const validated = await validate(deps, input);
  if ("error" in validated) return validated.error;
  const session = await findActiveSession(deps, input.sessionToken);

  if (input.via !== "confirmation" && !mayEndWithoutAsking(validated, session, input)) {
    return {
      kind: "confirm",
      locale: validated.locale,
      form: confirmationForm(validated),
      otherUser: validated.hint !== undefined && session !== undefined && validated.hint.sub !== session.userId,
    };
  }
  if (session !== undefined) await logout(deps, input.sessionToken);
  const sessionEnded = session !== undefined;
  if (validated.redirect === undefined) return { kind: "signed_out", locale: validated.locale, sessionEnded };
  return {
    kind: "redirect",
    location: redirectLocation(validated.redirect.uri, { state: validated.redirect.state }),
    sessionEnded,
  };
}

// §2 MUST ask without a hint or with a hint that is not the current session's; §6 asks for explicit confirmation
// without a valid hint. The IdP issues no sid, so "the current session's" is the same sub and the same auth_time.
function mayEndWithoutAsking(validated: ValidatedLogout, session: ActiveSession | undefined, input: EndSessionInput): boolean {
  if (session === undefined) {
    // A GET carries the Lax cookie, so no session means there is nothing to end. A cross-site POST does not carry it:
    // the browser may still hold a session, which only the same-origin confirmation can reach.
    return !(input.via === "post" && input.sessionToken === undefined);
  }
  const hint = validated.hint;
  return hint !== undefined && hint.sub === session.userId && hint.authTime === session.authTime;
}

function confirmationForm(validated: ValidatedLogout): readonly (readonly [string, string])[] {
  const form: (readonly [string, string])[] = [];
  if (validated.hintToken !== undefined) form.push(["id_token_hint", validated.hintToken]);
  if (validated.clientIdParam !== undefined) form.push(["client_id", validated.clientIdParam]);
  if (validated.redirect !== undefined) {
    form.push(["post_logout_redirect_uri", validated.redirect.uri]);
    if (validated.redirect.state !== undefined) form.push(["state", validated.redirect.state]);
  }
  form.push(["ui_locales", validated.locale]);
  return form;
}

async function validate(deps: OidcDeps, input: EndSessionInput): Promise<ValidatedLogout | { readonly error: EndSessionDecision }> {
  const params = collectParams(input.params);
  const locale = selectUiLocale(params.get("ui_locales")?.[0], input.acceptLanguage);
  function refuse(error: EndSessionErrorReason): { readonly error: EndSessionDecision } {
    return { error: { kind: "error_page", error, locale } };
  }
  function value(name: LogoutParameter): string | undefined {
    return params.get(name)?.[0];
  }

  if (LOGOUT_PARAMETERS.some((name) => (params.get(name)?.length ?? 0) > 1)) return refuse("invalid_request");
  const state = value("state");
  if (state !== undefined && state.length > MAX_STATE_LENGTH) return refuse("invalid_request");

  // §2: the OP MUST validate that it issued the hint; information that fails validation MUST NOT be used (§4).
  const hintToken = value("id_token_hint");
  let hint: LogoutIdTokenHint | undefined;
  if (hintToken !== undefined) {
    try {
      hint = await verifyLogoutIdTokenHint(hintToken, deps);
    } catch (error) {
      if (!(error instanceof InvalidTokenError)) throw error;
      return refuse("invalid_id_token_hint");
    }
  }

  const clientIdParam = value("client_id");
  if (clientIdParam !== undefined && !isClientId(clientIdParam)) return refuse("invalid_client");
  // §2: with both, client_id MUST be the client the ID token was issued to.
  if (clientIdParam !== undefined && hint !== undefined && clientIdParam !== hint.aud) return refuse("client_id_mismatch");
  const clientId = clientIdParam ?? hint?.aud;
  const client = clientId === undefined ? undefined : await loadLogoutClient(deps.db, clientId);
  // A client_id the RP sent must be "valid at the Authorization Server" (§2); a hint's aud was valid when issued.
  if (clientIdParam !== undefined && client === undefined) return refuse("invalid_client");

  // §3: redirect only to an exact match of a registered value. A disabled client's URIs are not trusted, as at
  // /authorize. Anything else is not an error: the logout goes on and ends on the IdP's own page.
  const uri = value("post_logout_redirect_uri");
  const registered = uri !== undefined && client !== undefined && client.enabled && client.postLogoutRedirectUris.includes(uri);
  return { locale, hintToken, hint, clientIdParam, redirect: registered ? { uri, state } : undefined };
}

// RFC 6749 §3.1, as at /authorize: a parameter sent without a value is treated as omitted.
function collectParams(pairs: EndSessionInput["params"]): ReadonlyMap<string, readonly string[]> {
  const params = new Map<string, string[]>();
  for (const [name, value] of pairs) {
    if (value === "") continue;
    const values = params.get(name);
    if (values === undefined) params.set(name, [value]);
    else values.push(value);
  }
  return params;
}
