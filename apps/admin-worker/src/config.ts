// The admin Worker's configuration (docs/design/deployment.md, "デプロイごとの入力" and "設定値"). Every value is
// validated before the first request is served, and a bad value refuses every request instead of being defaulted
// (design principle 4: fail-closed).
import { parseIssuer, type Issuer } from "@idp/core/shared";

/** The bindings and variables the deployment gives the admin Worker. Every member is untrusted until parsed. */
export type Env = {
  /** The D1 database the IdP Worker also binds. */
  readonly DB: D1Database;
  /** A Service Binding to the IdP Worker, read only for its discovery document (whether RS256 is enabled). */
  readonly IDP?: Fetcher;
  /** The issuer URL, the same value as the IdP Worker's; enrollment links are built from it. */
  readonly ISSUER?: string;
  /** The admin hostname, the only host this Worker answers on. */
  readonly ADMIN_HOST?: string;
  /** The certificate allowlist: a JSON array of `{"sha256": <lowercase hex>, "name": <admin name>}`. */
  readonly ADMIN_ALLOWLIST?: string;
  /** The version metadata binding; its ID becomes audit_log.writer_version. */
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
};

/** The validated configuration. */
export type AdminConfig = {
  readonly db: D1Database;
  readonly idp: Fetcher | undefined;
  readonly issuer: Issuer;
  readonly adminHost: string;
  /** Certificate SHA-256 fingerprint (lowercase hex) to admin name. */
  readonly allowlist: ReadonlyMap<string, string>;
  readonly writerVersion: string;
};

/** Thrown when the configuration is missing or malformed; the message names the setting, never a secret. */
export class InvalidConfigError extends Error {
  override readonly name = "InvalidConfigError";
}

/** A certificate fingerprint as the allowlist stores it: SHA-256 as 64 lowercase hex digits. */
export const FINGERPRINT = /^[0-9a-f]{64}$/;

// Admin names go to audit_log.admin_name and Workers Logs; the client ID's charset keeps them unambiguous on a line.
const ADMIN_NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

function parseAllowlist(value: string | undefined): ReadonlyMap<string, string> {
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

function isBinding(value: unknown, methods: readonly string[]): boolean {
  return typeof value === "object" && value !== null && methods.every((m) => typeof (value as Record<string, unknown>)[m] === "function");
}

/**
 * Parses and validates the environment.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} A binding or variable is missing or malformed.
 */
export function parseAdminConfig(env: Env): AdminConfig {
  if (!isBinding(env.DB, ["prepare", "batch"])) throw new InvalidConfigError("DB is not a D1 binding");
  let issuer: Issuer;
  try {
    issuer = parseIssuer(env.ISSUER);
  } catch (cause) {
    throw new InvalidConfigError("ISSUER is not a valid issuer", { cause });
  }
  const adminHost = parseAdminHost(env.ADMIN_HOST, issuer);
  const allowlist = parseAllowlist(env.ADMIN_ALLOWLIST);
  const versionId = env.CF_VERSION_METADATA?.id;
  if (typeof versionId !== "string" || versionId === "") throw new InvalidConfigError("CF_VERSION_METADATA has no version id");
  // A missing IDP binding is not fatal: it only means RS256 cannot be confirmed, which already fails closed.
  const idp = isBinding(env.IDP, ["fetch"]) ? env.IDP : undefined;
  return { db: env.DB, idp, issuer, adminHost, allowlist, writerVersion: `admin-worker@${versionId}` };
}

const parsed = new WeakMap<Env, AdminConfig | InvalidConfigError>();

/**
 * Returns the configuration of an environment, parsing it once. Workers hands the same `env` object to every
 * request of an isolate, so this is the startup validation; a failure is remembered and refuses every request.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} The environment is invalid; thrown again on every call.
 */
export function adminConfig(env: Env): AdminConfig {
  let entry = parsed.get(env);
  if (entry === undefined) {
    try {
      entry = parseAdminConfig(env);
    } catch (error) {
      if (!(error instanceof InvalidConfigError)) throw error;
      entry = error;
    }
    parsed.set(env, entry);
  }
  if (entry instanceof InvalidConfigError) throw entry;
  return entry;
}
