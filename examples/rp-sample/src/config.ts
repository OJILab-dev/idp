// The Worker's configuration: three plain vars from cloudflare.config.ts and two Worker Secrets. Every value is
// checked on each request and a missing or malformed one refuses the request (fail closed), so a deploy that ran
// before the secrets were set answers 500 instead of running half configured.
import { ConfigError } from "./errors.js";
import { importSealingKey } from "./sealed.js";

export { ConfigError } from "./errors.js";

/** The Worker's bindings, as untrusted strings. */
export type Env = {
  /** The IdP's issuer, `https://<host>` with no trailing slash; compared exactly with discovery, iss, and ID tokens. */
  readonly ISSUER?: string | undefined;
  /** The client_id registered with idpctl client_create. */
  readonly CLIENT_ID?: string | undefined;
  /** This Worker's own origin, `https://rp-sample.<subdomain>.workers.dev`; the redirect URI is `<origin>/callback`. */
  readonly ORIGIN?: string | undefined;
  /** Worker Secret: the confidential client's secret, from idpctl's --secret-out file. */
  readonly CLIENT_SECRET?: string | undefined;
  /** Worker Secret: 32 random bytes as base64, the AES-256-GCM key of the cookies. */
  readonly SESSION_KEY?: string | undefined;
};

/** The checked configuration. */
export type Config = {
  readonly issuer: string;
  readonly clientId: string;
  readonly origin: string;
  readonly redirectUri: string;
  /** `<origin>/signed-out`, registered with idpctl client_set_post_logout_redirects (RP-Initiated Logout 1.0 §3.1). */
  readonly postLogoutRedirectUri: string;
  readonly clientSecret: string;
  readonly sessionKey: CryptoKey;
};

// The IdP's client_id rule (packages/core/src/identifiers/identifiers.ts); checked here so a typo fails before a login.
const CLIENT_ID = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;

/**
 * Checks an https URL that must be exactly an origin, or an origin and a path without a trailing slash: the issuer
 * is compared by simple string comparison everywhere (OIDC Discovery §4.3, RFC 9207 §2.4), so the configured value
 * must already be in the form the IdP prints.
 *
 * @param value The untrusted value.
 * @param name The setting's name, for the error.
 * @param originOnly Whether a path is refused too.
 * @returns The value, unchanged.
 * @throws {ConfigError} The value is missing or not of that form.
 */
export function checkHttpsUrl(value: string | undefined, name: string, originOnly: boolean): string {
  let url: URL;
  try {
    url = new URL(value ?? "");
  } catch {
    throw new ConfigError(`${name} is not a URL`);
  }
  const canonical = url.pathname === "/" ? url.origin : `${url.origin}${url.pathname}`;
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || value !== canonical) {
    throw new ConfigError(`${name} must be an https URL with no trailing slash, query, or fragment`);
  }
  if (originOnly && value !== url.origin) throw new ConfigError(`${name} must be an origin`);
  return value;
}

/**
 * Reads and checks the configuration.
 *
 * @param env The Worker's bindings.
 * @returns The configuration, with the session key imported.
 * @throws {ConfigError} A setting is missing or malformed.
 */
export async function loadConfig(env: Env): Promise<Config> {
  const issuer = checkHttpsUrl(env.ISSUER, "ISSUER", false);
  const origin = checkHttpsUrl(env.ORIGIN, "ORIGIN", true);
  const clientId = env.CLIENT_ID;
  if (clientId === undefined || !CLIENT_ID.test(clientId)) throw new ConfigError("CLIENT_ID is not a client_id");
  const clientSecret = env.CLIENT_SECRET;
  if (clientSecret === undefined || clientSecret === "") throw new ConfigError("CLIENT_SECRET is not set");
  const sessionKey = await importSealingKey(env.SESSION_KEY);
  return { issuer, clientId, origin, redirectUri: `${origin}/callback`, postLogoutRedirectUri: `${origin}/signed-out`, clientSecret, sessionKey };
}
