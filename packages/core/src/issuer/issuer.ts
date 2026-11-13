// The issuer: the one configured URL from which the RP ID, the WebAuthn origin, the discovery endpoints, and the
// access token aud are all derived (docs/design/deployment.md), so they cannot disagree.

/** The validated issuer and the values derived from it. */
export type Issuer = {
  /** The issuer URL exactly as configured: `https://<host>`, the `iss` of every token. */
  readonly url: string;
  /** The WebAuthn RP ID: the issuer's host. */
  readonly rpId: string;
  /** The WebAuthn origin; equal to `url`, since the issuer has no port, path, or trailing slash. */
  readonly origin: string;
};

/** Thrown when the issuer setting is unset or not of the form `https://<host>`. */
export class InvalidIssuerError extends Error {
  override readonly name = "InvalidIssuerError";
}

const IPV4 = /^[0-9.]+$/;

/**
 * Parses the issuer setting fail-closed.
 *
 * The value must already be canonical: it is compared after URL parsing with `https://` plus the parsed host, so
 * anything the URL parser would rewrite (an uppercase host, an explicit `:443`, an empty `?` or `#`) is rejected
 * instead of silently normalised, and the configured string is the exact `iss` RPs compare against.
 *
 * @param value The raw setting (a Worker environment variable); `undefined` when unset.
 * @returns The issuer and its derived RP ID and origin.
 * @throws {InvalidIssuerError} The value is unset or empty; is not an https URL; has userinfo, a port, a path
 *   (including a trailing slash), a query, or a fragment; is not in canonical form; has a trailing dot; or its
 *   host is an IP address (WebAuthn RP IDs are domains, and the host must be a name the certificate covers).
 */
export function parseIssuer(value: string | undefined): Issuer {
  if (value === undefined || value === "") {
    throw new InvalidIssuerError("issuer is not set");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidIssuerError("issuer is not a URL");
  }
  const host = url.hostname;
  if (url.protocol !== "https:" || host === "" || value !== `https://${host}`) {
    throw new InvalidIssuerError("issuer must be exactly https://<host>");
  }
  if (host.startsWith("[") || IPV4.test(host)) {
    throw new InvalidIssuerError("issuer host must not be an IP address");
  }
  if (host.endsWith(".")) {
    throw new InvalidIssuerError("issuer host must not end with a dot");
  }
  return { url: value, rpId: host, origin: value };
}
