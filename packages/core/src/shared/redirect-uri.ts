// Redirect URI registration rules (docs/design/clients.md). The admin Worker applies them when a client's URIs are
// set; the IdP Worker compares a request's redirect_uri against the stored strings exactly and may re-check stored
// rows with the same function, so a broken row is rejected rather than trusted.

/** The three registration forms of RFC 8252 §7, of which confidential clients may use only `https`. */
export type RedirectUriKind = "https" | "loopback" | "custom-scheme";

/** The client types of RFC 6749 §2.1. */
export type ClientType = "confidential" | "public";

// Long enough for any real callback, short enough that a pasted blob is not stored and echoed into every audit row.
const MAX_REDIRECT_URI_LENGTH = 2000;

// Printable ASCII without space: anything else must already be percent-encoded, which the canonical check enforces.
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

// RFC 8252 §7.1: a reverse domain name of labels, then ":/" and a path with no authority.
const CUSTOM_SCHEME = /^([a-z][a-z0-9.-]*):\/(?!\/)/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

// RFC 8252 §7.3 and §8.3: loopback redirects use the IP literals, never the name "localhost".
const LOOPBACK_HOSTS: readonly string[] = ["127.0.0.1", "[::1]"];

/**
 * Classifies a redirect URI by its registration form, or rejects it.
 *
 * Every accepted URI is already in the form the WHATWG URL parser would print, so the stored string is the one
 * exact-match comparison uses (RFC 9700 §2.1) and no second spelling of it exists. Rejected: fragments (RFC 6749
 * §3.1.2), userinfo, `*` wildcards, `localhost`, a port on a loopback URI (the port is chosen at run time, RFC 8252
 * §7.3), plain http to anything but 127.0.0.1 or [::1], and custom schemes that are not reverse domain names.
 *
 * @param value The untrusted URI.
 * @returns The form, or null when the URI may not be registered.
 */
export function classifyRedirectUri(value: string): RedirectUriKind | null {
  if (value.length > MAX_REDIRECT_URI_LENGTH || !PRINTABLE_ASCII.test(value) || value.includes("#") || value.includes("*")) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.href !== value || url.username !== "" || url.password !== "") return null;
  if (url.protocol === "https:") {
    return url.hostname === "" || url.hostname === "localhost" ? null : "https";
  }
  if (url.protocol === "http:") {
    return LOOPBACK_HOSTS.includes(url.hostname) && url.port === "" ? "loopback" : null;
  }
  const scheme = CUSTOM_SCHEME.exec(value)?.[1];
  if (scheme === undefined) return null;
  const labels = scheme.split(".");
  return labels.length >= 2 && labels.every((label) => DOMAIN_LABEL.test(label)) ? "custom-scheme" : null;
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
