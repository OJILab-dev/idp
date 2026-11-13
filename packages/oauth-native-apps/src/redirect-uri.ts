// The three redirect URI forms of OAuth 2.0 for Native Apps (RFC 8252 §7): a claimed https URI (§7.2), a loopback IP
// literal over http (§7.3), and a private-use URI scheme named by a reverse domain name (§7.1). A URI is accepted only
// in the exact form the WHATWG URL parser prints, so the stored string is the one an exact comparison uses
// (RFC 9700 §2.1) and no second spelling of it exists. Length limits and character-set policy belong to the caller.

/** The redirect URI forms of RFC 8252 §7. */
export type RedirectUriKind = "https" | "loopback" | "custom-scheme";

/**
 * The loopback hosts of RFC 8252 §7.3, as the URL parser prints them: only the IP literals, never the name
 * "localhost", which §8.3 recommends against. Classification and matching both use this one list.
 */
export const LOOPBACK_REDIRECT_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]"]);

// A private-use scheme is a reverse domain name of labels, then ":/" and a path with no authority (RFC 8252 §7.1).
const CUSTOM_SCHEME = /^([a-z][a-z0-9.-]*):\/(?!\/)/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Tells which RFC 8252 form a redirect URI has, if any, for registering it.
 *
 * Rejected: a URI the URL parser would print differently, a fragment (RFC 6749 §3.1.2), userinfo, the name
 * `localhost` or a name under it (RFC 8252 §8.3; RFC 6761 §6.3), a port on a loopback URI (the port is chosen at run
 * time, RFC 8252 §7.3), plain http to anything but 127.0.0.1 or [::1], and private-use schemes that are not reverse
 * domain names.
 *
 * @param value The untrusted URI.
 * @returns The form, or null when the URI has none of the three forms.
 */
export function classifyRedirectUriForm(value: string): RedirectUriKind | null {
  if (value.includes("#")) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.href !== value || url.username !== "" || url.password !== "") return null;
  if (url.protocol === "https:") {
    // A trailing dot names the same host (a fully qualified name), and *.localhost resolves to loopback too
    // (RFC 6761 §6.3), so neither may slip past the localhost ban of RFC 8252 §8.3.
    const host = url.hostname.endsWith(".") ? url.hostname.slice(0, -1) : url.hostname;
    return host === "" || host === "localhost" || host.endsWith(".localhost") ? null : "https";
  }
  if (url.protocol === "http:") {
    return LOOPBACK_REDIRECT_HOSTS.has(url.hostname) && url.port === "" ? "loopback" : null;
  }
  const scheme = CUSTOM_SCHEME.exec(value)?.[1];
  if (scheme === undefined) return null;
  const labels = scheme.split(".");
  return labels.length >= 2 && labels.every((label) => DOMAIN_LABEL.test(label)) ? "custom-scheme" : null;
}
