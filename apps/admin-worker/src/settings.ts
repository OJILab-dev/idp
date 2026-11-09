// The parsers of the admin Worker's deployment settings, shared by the Worker (src/config.ts) and the deployment
// configuration (cloudflare.config.ts), so the deploy refuses exactly the values the Worker would refuse.
//
// cf loads cloudflare.config.ts with Node's own module loader, which does not map the `.js` specifiers of this
// repository's TypeScript to `.ts` files. This module therefore imports only through package exports that point at a
// file with no relative imports (`@idp/core/shared/issuer`), and is itself imported there as
// `@idp/admin-worker/settings`. Do not add a relative import here.
import { parseIssuer, type Issuer } from "@idp/core/shared/issuer";

/** Thrown when the configuration is missing or malformed; the message names the setting, never a secret. */
export class InvalidConfigError extends Error {
  override readonly name = "InvalidConfigError";
}

/** A certificate fingerprint as the allowlist stores it: SHA-256 as 64 lowercase hex digits. */
export const FINGERPRINT = /^[0-9a-f]{64}$/;

// Admin names go to audit_log.admin_name and Workers Logs; the client ID's charset keeps them unambiguous on a line.
const ADMIN_NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

/**
 * Parses ADMIN_ALLOWLIST.
 *
 * @param value The JSON text of the allowlist.
 * @returns Certificate SHA-256 fingerprint (lowercase hex) to admin name.
 * @throws {InvalidConfigError} The value is unset, not JSON, empty, or has a malformed or repeated entry.
 */
export function parseAllowlist(value: string | undefined): ReadonlyMap<string, string> {
  if (value === undefined) throw new InvalidConfigError("ADMIN_ALLOWLIST is not set");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new InvalidConfigError("ADMIN_ALLOWLIST is not JSON");
  }
  if (!Array.isArray(parsed) || parsed.length === 0) throw new InvalidConfigError("ADMIN_ALLOWLIST must be a non-empty array");
  const allowlist = new Map<string, string>();
  for (const [i, entry] of (parsed as readonly unknown[]).entries()) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new InvalidConfigError(`ADMIN_ALLOWLIST[${i}] is not an object`);
    const { sha256, name, ...rest } = entry as Record<string, unknown>;
    if (Object.keys(rest).length > 0) throw new InvalidConfigError(`ADMIN_ALLOWLIST[${i}] has unknown members`);
    // The allowlist is reviewed as written, so it must already be canonical rather than normalised here.
    if (typeof sha256 !== "string" || !FINGERPRINT.test(sha256)) throw new InvalidConfigError(`ADMIN_ALLOWLIST[${i}].sha256 is not lowercase hex SHA-256`);
    if (typeof name !== "string" || !ADMIN_NAME.test(name)) throw new InvalidConfigError(`ADMIN_ALLOWLIST[${i}].name is not a valid admin name`);
    if (allowlist.has(sha256)) throw new InvalidConfigError(`ADMIN_ALLOWLIST[${i}].sha256 is repeated`);
    allowlist.set(sha256, name);
  }
  return allowlist;
}

/**
 * Parses ADMIN_HOST.
 *
 * @param value The admin hostname.
 * @param issuer The parsed issuer; the admin host must differ from its host.
 * @returns The canonical admin hostname.
 * @throws {InvalidConfigError} The value is unset, not a canonical hostname, or equal to the issuer host.
 */
export function parseAdminHost(value: string | undefined, issuer: Issuer): string {
  if (value === undefined || value === "") throw new InvalidConfigError("ADMIN_HOST is not set");
  // The issuer's rules are the hostname's rules: canonical, no port, no IP address, no trailing dot.
  let host: string;
  try {
    host = parseIssuer(`https://${value}`).rpId;
  } catch {
    throw new InvalidConfigError("ADMIN_HOST must be a canonical hostname");
  }
  // Serving the admin API on the issuer host would put it next to the public endpoints (design principle 1).
  if (host === issuer.rpId) throw new InvalidConfigError("ADMIN_HOST must differ from the issuer host");
  return host;
}
