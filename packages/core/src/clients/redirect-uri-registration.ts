// Redirect URI registration rules (docs/design/clients.md): which URIs a client may register. The admin Worker
// applies them when a client's URIs are set, and the IdP Worker may re-check stored rows with the same function, so
// a broken row is rejected rather than trusted. The three forms themselves are RFC 8252's and come from
// @idp/oauth-native-apps, which also matches a request's redirect_uri against the registered values; this module adds
// the IdP's own limits in front of the classification.
import { classifyRedirectUriForm, type RedirectUriKind } from "@idp/oauth-native-apps";

/** The client types of RFC 6749 §2.1. */
export type ClientType = "confidential" | "public";

// Long enough for any real callback, short enough that a pasted blob is not stored and echoed into every audit row.
const MAX_REDIRECT_URI_LENGTH = 2000;

// Printable ASCII without space: anything else must already be percent-encoded, which the canonical check enforces.
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

/**
 * Classifies a redirect URI by its registration form, or rejects it.
 *
 * The IdP first refuses URIs longer than 2000 characters, URIs with anything but printable ASCII, and any `*`, so
 * nothing that looks like a wildcard is stored. The rest is the RFC 8252 classification: the URI must be in the form
 * the URL parser prints, with no fragment or userinfo, and be https to a host other than localhost, http to a
 * loopback IP literal without a port, or a reverse-domain private-use scheme.
 *
 * @param value The untrusted URI.
 * @returns The form, or null when the URI may not be registered.
 */
export function classifyRedirectUri(value: string): RedirectUriKind | null {
  if (value.length > MAX_REDIRECT_URI_LENGTH || !PRINTABLE_ASCII.test(value) || value.includes("*")) return null;
  return classifyRedirectUriForm(value);
}

/** The post-logout redirect URI rules as a noun phrase, for the OpenAPI description and validation messages. */
export const POST_LOGOUT_REDIRECT_URI_RULES =
  `an absolute https URI of at most ${MAX_REDIRECT_URI_LENGTH} printable ASCII characters in canonical form (as the URL parser prints it), compared exactly, with no fragment, userinfo, '*' wildcard, localhost host (nor *.localhost, with or without a trailing dot), or state query parameter (the IdP appends the request's state)`;

/**
 * Checks whether a client may register a URI as an RP-Initiated Logout post-logout redirect URI (docs/design/clients.md):
 * the https form of the redirect URI rules, for every client type, and no `state` query parameter, because the IdP
 * appends the request's `state` to the registered query (RP-Initiated Logout 1.0 §3) and two values would let the RP
 * read a fixed one. The admin Worker and the audit log check use this one function.
 *
 * @param value The untrusted URI.
 * @returns Whether the URI may be registered.
 */
export function isPostLogoutRedirectUriRegistrable(value: string): boolean {
  return classifyRedirectUri(value) === "https" && !new URL(value).searchParams.has("state");
}

/**
 * Checks whether a client of the given type may register a redirect URI (docs/design/clients.md): confidential
 * clients only https, public clients any of the three forms.
 *
 * @param value The untrusted URI.
 * @param clientType The client's type.
 * @returns Whether the URI may be registered for that type.
 */
export function isRedirectUriAllowed(value: string, clientType: ClientType): boolean {
  const kind = classifyRedirectUri(value);
  return kind !== null && (clientType === "public" || kind === "https");
}
