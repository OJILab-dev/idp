// redirect_uri matching: exact string comparison, with the one exception RFC 8252 §7.3 requires for native apps on a
// loopback IP literal, whose port is chosen at run time (RFC 9700 §2.1, docs/design/clients.md).

// Only IP literals count as loopback; localhost is NOT RECOMMENDED (RFC 8252 §8.3) and is compared exactly.
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]"]);

/**
 * Checks a requested redirect_uri against one registered value.
 *
 * Without the loopback exception the strings must be identical: no case folding, no default-port or trailing-slash
 * normalisation, so a URI the RP did not register can never pass by being spelled differently. For a registered
 * `http` loopback URI the port is ignored, but the requested value must already be in the URL parser's canonical form
 * so that dot segments or other rewrites cannot turn a different path into the registered one.
 *
 * @param registered A value from `clients.redirect_uris_json`.
 * @param requested The untrusted `redirect_uri` parameter.
 * @returns Whether the request may be redirected to `requested`.
 */
export function matchesRegisteredRedirectUri(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  const registeredUrl = parseLoopback(registered);
  const requestedUrl = parseLoopback(requested);
  if (registeredUrl === undefined || requestedUrl === undefined || requestedUrl.href !== requested) return false;
  return (
    registeredUrl.hostname === requestedUrl.hostname &&
    registeredUrl.pathname === requestedUrl.pathname &&
    registeredUrl.search === requestedUrl.search
  );
}

/**
 * Finds whether a requested redirect_uri matches any registered value.
 *
 * @param registered The client's registered redirect URIs.
 * @param requested The untrusted `redirect_uri` parameter.
 * @returns Whether some registered value matches.
 */
export function isRegisteredRedirectUri(registered: readonly string[], requested: string): boolean {
  return registered.some((value) => matchesRegisteredRedirectUri(value, requested));
}

function parseLoopback(value: string): URL | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname)) return undefined;
  if (url.username !== "" || url.password !== "" || url.hash !== "" || value.includes("#")) return undefined;
  return url;
}
