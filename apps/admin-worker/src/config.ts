// The admin Worker's configuration (docs/design/deployment.md, "デプロイごとの入力" and "設定値"; docs/design/idpctl.md,
// the setting names). Every value is validated before the first request is served, and a bad value refuses every
// request instead of being defaulted (design principle 4: fail-closed).
import type { AdminSigningKey } from "@idp/core/admin";
import { InvalidHostingError, checkHostingHosts, parseHostingMode, type HostingMode } from "@idp/core/hosting";
import { parseIssuer, type Issuer } from "@idp/core/issuer";

/**
 * The IdP Worker's internal entrypoint (`IdpInternal`), reached over the `IDP` Service Binding by RPC. The public
 * fetch path is not used: a binding call carries no request.cf or client IP, so the IdP Worker's TLS and rate-limit
 * checks would refuse it.
 */
export interface IdpInternalBinding {
  /**
   * Reads the IdP Worker's discovery document, computed by the same code as `/.well-known/openid-configuration`.
   * Read-only and idempotent.
   *
   * @returns The document as structured-cloned data; untrusted until the caller checks its shape and issuer.
   * @throws {Error} The IdP Worker's configuration is invalid or the call failed; the caller treats it as RS256
   *   disabled.
   */
  discovery(): Promise<unknown>;
}

/** The bindings and variables the deployment gives the admin Worker. Every member is untrusted until parsed. */
export type Env = {
  /** The D1 database the IdP Worker also binds. */
  readonly DB: D1Database;
  /** A Service Binding to the IdP Worker's `IdpInternal` entrypoint, read only to learn whether RS256 is enabled. */
  readonly IDP?: IdpInternalBinding;
  /** The issuer URL, the same value as the IdP Worker's; enrollment links are built from it. */
  readonly ISSUER?: string;
  /** The admin hostname, the only host this Worker answers on. */
  readonly ADMIN_HOST?: string;
  /** `custom_domain` or `workers_dev`; checked against the hosts only (docs/design/hosting-modes.md 1.4). */
  readonly HOSTING_MODE?: string;
  /** The signing-key allowlist: a JSON array of `{"keyid", "name", "public_key"}` (hosting-modes.md 3.7). */
  readonly ADMIN_SIGNING_KEYS?: string;
  /** The Rate Limiting binding, counted per client IP before the signature is parsed (hosting-modes.md 6.2). */
  readonly RATE_LIMITER?: RateLimit;
  /** The version metadata binding; its ID becomes audit_log.writer_version. */
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
};

/** The validated configuration. */
export type AdminConfig = {
  readonly db: D1Database;
  readonly idp: IdpInternalBinding | undefined;
  readonly issuer: Issuer;
  readonly adminHost: string;
  readonly hostingMode: HostingMode;
  /** The allowlist by keyid, each public key imported for ECDSA P-384 verification. */
  readonly signingKeys: ReadonlyMap<string, AdminSigningKey>;
  readonly rateLimiter: RateLimit;
  readonly writerVersion: string;
};

/** Thrown when the configuration is missing or malformed; the message names the setting, never a key. */
export class InvalidConfigError extends Error {
  override readonly name = "InvalidConfigError";
}

/** A keyid as the allowlist stores it: the SHA-256 of the SPKI DER as 64 lowercase hex digits. */
export const KEYID = /^[0-9a-f]{64}$/;

// Admin names go to audit_log.admin_name and Workers Logs; the client ID's charset keeps them unambiguous on a line.
const ADMIN_NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
// Padded base64 on one line (hosting-modes.md 3.7); the round trip below rejects every other spelling of the bytes.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64(value: string): Uint8Array | undefined {
  if (value === "" || !BASE64.test(value)) return undefined;
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  // Non-zero padding bits decode to the same bytes as another string; only the canonical spelling is reviewed.
  return btoa(binary) === value ? bytes : undefined;
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function importP384(der: Uint8Array): Promise<CryptoKey | undefined> {
  try {
    return await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
  } catch {
    // Not a P-384 SPKI (another curve, another algorithm, or a point not on the curve).
    return undefined;
  }
}

async function parseSigningKeys(value: string | undefined): Promise<ReadonlyMap<string, AdminSigningKey>> {
  if (value === undefined) throw new InvalidConfigError("ADMIN_SIGNING_KEYS is not set");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new InvalidConfigError("ADMIN_SIGNING_KEYS is not JSON");
  }
  // An empty list would admit nobody; it is refused like any other error so that the misconfiguration is loud.
  if (!Array.isArray(parsed) || parsed.length === 0) throw new InvalidConfigError("ADMIN_SIGNING_KEYS must be a non-empty array");
  const keys = new Map<string, AdminSigningKey>();
  for (const [i, entry] of (parsed as readonly unknown[]).entries()) {
    const at = `ADMIN_SIGNING_KEYS[${String(i)}]`;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new InvalidConfigError(`${at} is not an object`);
    const { keyid, name, public_key: publicKey, ...rest } = entry as Record<string, unknown>;
    if (Object.keys(rest).length > 0) throw new InvalidConfigError(`${at} has unknown members`);
    // The allowlist is reviewed as written, so it must already be canonical rather than normalised here.
    if (typeof keyid !== "string" || !KEYID.test(keyid)) throw new InvalidConfigError(`${at}.keyid is not lowercase hex SHA-256`);
    if (typeof name !== "string" || !ADMIN_NAME.test(name)) throw new InvalidConfigError(`${at}.name is not a valid admin name`);
    const der = typeof publicKey === "string" ? decodeBase64(publicKey) : undefined;
    if (der === undefined) throw new InvalidConfigError(`${at}.public_key is not one-line padded base64`);
    const key = await importP384(der);
    if (key === undefined) throw new InvalidConfigError(`${at}.public_key is not an ECDSA P-384 SPKI`);
    // keyid is computable from public_key; it is written so a reviewer can compare it with 1Password and the audit
    // log, and checked here so that the written value can never drift from the key.
    if (hex(await crypto.subtle.digest("SHA-256", der)) !== keyid) throw new InvalidConfigError(`${at}.keyid is not the SHA-256 of its public_key`);
    if (keys.has(keyid)) throw new InvalidConfigError(`${at}.keyid is repeated`);
    keys.set(keyid, { keyid, name, publicKey: key });
  }
  return keys;
}

function parseAdminHost(value: string | undefined, issuer: Issuer): string {
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

function parseMode(value: string | undefined, issuer: Issuer, adminHost: string): HostingMode {
  try {
    const mode = parseHostingMode(value);
    checkHostingHosts(mode, issuer.rpId, adminHost);
    return mode;
  } catch (cause) {
    if (!(cause instanceof InvalidHostingError)) throw cause;
    throw new InvalidConfigError(`HOSTING_MODE does not match ISSUER and ADMIN_HOST: ${cause.message}`, { cause });
  }
}

function isBinding(value: unknown, methods: readonly string[]): boolean {
  return typeof value === "object" && value !== null && methods.every((m) => typeof (value as Record<string, unknown>)[m] === "function");
}

/**
 * Parses and validates the environment, importing the signing keys.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} A binding or variable is missing or malformed: no D1 or Rate Limiting binding, an
 *   invalid issuer or admin host, a hosting mode that is unknown or does not match the hosts, an allowlist that is
 *   empty or malformed (including a keyid that is not the SHA-256 of its public key), or no version ID.
 */
export async function parseAdminConfig(env: Env): Promise<AdminConfig> {
  if (!isBinding(env.DB, ["prepare", "batch"])) throw new InvalidConfigError("DB is not a D1 binding");
  // Without the limiter the signature verification would lose its only guard against floods of CPU time, so its
  // absence refuses every request instead of skipping the count (docs/design/hosting-modes.md 6.2).
  if (!isBinding(env.RATE_LIMITER, ["limit"])) throw new InvalidConfigError("RATE_LIMITER is not a Rate Limiting binding");
  let issuer: Issuer;
  try {
    issuer = parseIssuer(env.ISSUER);
  } catch (cause) {
    throw new InvalidConfigError("ISSUER is not a valid issuer", { cause });
  }
  const adminHost = parseAdminHost(env.ADMIN_HOST, issuer);
  const hostingMode = parseMode(env.HOSTING_MODE, issuer, adminHost);
  const signingKeys = await parseSigningKeys(env.ADMIN_SIGNING_KEYS);
  const versionId = env.CF_VERSION_METADATA?.id;
  if (typeof versionId !== "string" || versionId === "") throw new InvalidConfigError("CF_VERSION_METADATA has no version id");
  // A missing IDP binding is not fatal: it only means RS256 cannot be confirmed, which already fails closed.
  const idp = isBinding(env.IDP, ["discovery"]) ? env.IDP : undefined;
  return {
    db: env.DB,
    idp,
    issuer,
    adminHost,
    hostingMode,
    signingKeys,
    rateLimiter: env.RATE_LIMITER as RateLimit,
    writerVersion: `admin-worker@${versionId}`,
  };
}

const parsed = new WeakMap<Env, Promise<AdminConfig>>();

/**
 * Returns the configuration of an environment, parsing it once. Workers hands the same `env` object to every
 * request of an isolate, so this is the startup validation, and the imported keys are kept for the isolate. A
 * failure is remembered and refuses every request.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} The environment is invalid; rejected again on every call.
 */
export function adminConfig(env: Env): Promise<AdminConfig> {
  let entry = parsed.get(env);
  if (entry === undefined) {
    entry = parseAdminConfig(env);
    parsed.set(env, entry);
  }
  return entry;
}
