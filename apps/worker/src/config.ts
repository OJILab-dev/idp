// The IdP Worker's configuration (docs/design/deployment.md, "設定値" and "署名鍵"). The issuer, the D1 binding, and the
// signing keys are validated before the first request is served, and a bad value refuses every request instead of
// being defaulted (design principle 4: fail-closed).
import { createD1Database } from "@idp/cloudflare/d1";
import { InvalidHostingError, checkHostingHosts, parseHostingMode } from "@idp/hosting";
import { InvalidIssuerError, parseIssuer, type Issuer } from "@idp/issuer";
import type { Database } from "@idp/db";
import { InvalidSigningKeyConfigError, loadSigningKeys, type SigningKeySet } from "./domain/index.js";

/** The bindings, variables, and Secrets the deployment gives the IdP Worker. Every member is untrusted until parsed. */
export type Env = {
  readonly DB: D1Database;
  /** The issuer URL, `https://<host>`; every derived value (RP ID, origin, endpoints, aud) comes from it. */
  readonly ISSUER?: string;
  /**
   * The hosting mode, `custom_domain` or `workers_dev` (docs/design/hosting-modes.md 1.4). Nothing branches on it: it
   * only has to agree with the issuer's host, so a configuration that mixes the modes refuses every request.
   */
  readonly HOSTING_MODE?: string;
  /** Worker Secrets, each a private JWK as JSON (docs/design/tokens.md, "署名鍵"). Only the Ed25519 current is required. */
  readonly SIGNING_KEY_ED25519_CURRENT?: string;
  readonly SIGNING_KEY_ED25519_PREVIOUS?: string;
  readonly SIGNING_KEY_RSA_CURRENT?: string;
  readonly SIGNING_KEY_RSA_PREVIOUS?: string;
  /** The version metadata binding; its ID becomes audit_log.writer_version of the user's own passkey operations. */
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  /** The Rate Limiting binding, counted per client IP before any route runs (docs/design/free-tier.md). */
  readonly RATE_LIMITER?: RateLimit;
  /** The static assets binding; the Worker runs first on every request and serves the pages through it. */
  readonly ASSETS?: Fetcher;
};

/** The validated configuration. */
export type WorkerConfig = {
  readonly db: Database;
  readonly issuer: Issuer;
  readonly keys: SigningKeySet;
  /** `idp@<version id>`, written to the audit rows of passkey enrollment, add, and self-revocation. */
  readonly writerVersion: string;
  readonly rateLimiter: RateLimit;
  readonly assets: Fetcher;
};

/** Thrown when the configuration is missing or malformed; the message names the setting, never a key. */
export class InvalidConfigError extends Error {
  override readonly name = "InvalidConfigError";
}

function isD1Binding(value: unknown): value is D1Database {
  return typeof value === "object" && value !== null && ["prepare", "batch"].every((m) => typeof (value as Record<string, unknown>)[m] === "function");
}

function isAssetsBinding(value: unknown): value is Fetcher {
  return typeof value === "object" && value !== null && typeof (value as Record<string, unknown>)["fetch"] === "function";
}

function isRateLimitBinding(value: unknown): value is RateLimit {
  return typeof value === "object" && value !== null && typeof (value as Record<string, unknown>)["limit"] === "function";
}

/**
 * Parses and validates the environment, importing the signing keys.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} The D1 binding is missing, the Rate Limiting binding is missing, the assets binding is missing,
 *   the issuer is invalid, the hosting mode is missing or does not match the issuer's host,
 *   the signing keys are invalid, or the version metadata has no version ID.
 */
export async function parseWorkerConfig(env: Env): Promise<WorkerConfig> {
  if (!isD1Binding(env.DB)) throw new InvalidConfigError("DB is not a D1 binding");
  // Without the limiter the pre-authentication D1 writes would lose their only in-Worker guard, so its absence
  // refuses every request instead of skipping the count (docs/design/domain-placement.md, 4).
  if (!isRateLimitBinding(env.RATE_LIMITER)) throw new InvalidConfigError("RATE_LIMITER is not a Rate Limiting binding");
  // Every request runs the Worker first (docs/design/free-tier.md), so without the binding no page can be served.
  if (!isAssetsBinding(env.ASSETS)) throw new InvalidConfigError("ASSETS is not a static assets binding");
  const versionId = env.CF_VERSION_METADATA?.id;
  if (typeof versionId !== "string" || versionId === "") throw new InvalidConfigError("CF_VERSION_METADATA has no version id");
  let issuer: Issuer;
  try {
    issuer = parseIssuer(env.ISSUER);
  } catch (error) {
    if (!(error instanceof InvalidIssuerError)) throw error;
    throw new InvalidConfigError(`ISSUER: ${error.message}`);
  }
  // The same shared-core rules as the admin Worker and both cloudflare.config.ts files, so the three places of
  // hosting-modes.md 1.4 cannot disagree on what a mixed configuration is.
  try {
    checkHostingHosts(parseHostingMode(env.HOSTING_MODE), issuer.rpId);
  } catch (error) {
    if (!(error instanceof InvalidHostingError)) throw error;
    throw new InvalidConfigError(`HOSTING_MODE does not match ISSUER: ${error.message}`, { cause: error });
  }
  let keys: SigningKeySet;
  try {
    keys = await loadSigningKeys({
      ed25519Current: env.SIGNING_KEY_ED25519_CURRENT,
      ed25519Previous: env.SIGNING_KEY_ED25519_PREVIOUS,
      rsaCurrent: env.SIGNING_KEY_RSA_CURRENT,
      rsaPrevious: env.SIGNING_KEY_RSA_PREVIOUS,
    });
  } catch (error) {
    // The core's message names only the slot and the rule; it never quotes key material.
    if (!(error instanceof InvalidSigningKeyConfigError)) throw error;
    throw new InvalidConfigError(`signing keys: ${error.message}`);
  }
  return { db: createD1Database(env.DB), issuer, keys, writerVersion: `idp@${versionId}`, rateLimiter: env.RATE_LIMITER, assets: env.ASSETS };
}

const parsed = new WeakMap<Env, Promise<WorkerConfig>>();

/**
 * Returns the configuration of an environment, parsing it once. Workers hands the same `env` object to every
 * request of an isolate, so this is the startup validation, and the imported keys are cached at module scope
 * (docs/design/tokens.md). A failure is remembered and refuses every request.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} The environment is invalid; thrown again on every call.
 */
export function workerConfig(env: Env): Promise<WorkerConfig> {
  let entry = parsed.get(env);
  if (entry === undefined) {
    entry = parseWorkerConfig(env);
    parsed.set(env, entry);
  }
  return entry;
}
