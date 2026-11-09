// The admin Worker's configuration (docs/design/deployment.md, "デプロイごとの入力" and "設定値"). Every value is
// validated before the first request is served, and a bad value refuses every request instead of being defaulted
// (design principle 4: fail-closed).
import { parseIssuer, type Issuer } from "@idp/core/shared";
import { InvalidConfigError, parseAdminHost, parseAllowlist } from "./settings.js";

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
  /** The certificate allowlist: a JSON array of `{"sha256": <lowercase hex>, "name": <admin name>}`. */
  readonly ADMIN_ALLOWLIST?: string;
  /** The version metadata binding; its ID becomes audit_log.writer_version. */
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
};

/** The validated configuration. */
export type AdminConfig = {
  readonly db: D1Database;
  readonly idp: IdpInternalBinding | undefined;
  readonly issuer: Issuer;
  readonly adminHost: string;
  /** Certificate SHA-256 fingerprint (lowercase hex) to admin name. */
  readonly allowlist: ReadonlyMap<string, string>;
  readonly writerVersion: string;
};

export { FINGERPRINT, InvalidConfigError } from "./settings.js";

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
  const idp = isBinding(env.IDP, ["discovery"]) ? env.IDP : undefined;
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
