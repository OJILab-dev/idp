// The IdP Worker's configuration (docs/design/deployment.md, "設定値" and "署名鍵"). The issuer, the D1 binding, and the
// signing keys are validated before the first request is served, and a bad value refuses every request instead of
// being defaulted (design principle 4: fail-closed).
import { createD1Database } from "@idp/d1-adapter";
import { InvalidIssuerError, parseIssuer, type Database, type Issuer } from "@idp/core/shared";
import { InvalidSigningKeyConfigError, loadSigningKeys, type SigningKeySet } from "@idp/core/user";

/** The bindings, variables, and Secrets the deployment gives the IdP Worker. Every member is untrusted until parsed. */
export type Env = {
  readonly DB: D1Database;
  /** The issuer URL, `https://<host>`; every derived value (RP ID, origin, endpoints, aud) comes from it. */
  readonly ISSUER?: string;
  /** Worker Secrets, each a private JWK as JSON (docs/design/tokens.md, "署名鍵"). Only the Ed25519 current is required. */
  readonly SIGNING_KEY_ED25519_CURRENT?: string;
  readonly SIGNING_KEY_ED25519_PREVIOUS?: string;
  readonly SIGNING_KEY_RSA_CURRENT?: string;
  readonly SIGNING_KEY_RSA_PREVIOUS?: string;
};

/** The validated configuration. */
export type WorkerConfig = {
  readonly db: Database;
  readonly issuer: Issuer;
  readonly keys: SigningKeySet;
};

/** Thrown when the configuration is missing or malformed; the message names the setting, never a key. */
export class InvalidConfigError extends Error {
  override readonly name = "InvalidConfigError";
}

function isD1Binding(value: unknown): value is D1Database {
  return typeof value === "object" && value !== null && ["prepare", "batch"].every((m) => typeof (value as Record<string, unknown>)[m] === "function");
}

/**
 * Parses and validates the environment, importing the signing keys.
 *
 * @param env The Worker's environment.
 * @returns The configuration.
 * @throws {InvalidConfigError} The D1 binding is missing, the issuer is invalid, or the signing keys are invalid.
 */
export async function parseWorkerConfig(env: Env): Promise<WorkerConfig> {
  if (!isD1Binding(env.DB)) throw new InvalidConfigError("DB is not a D1 binding");
  let issuer: Issuer;
  try {
    issuer = parseIssuer(env.ISSUER);
  } catch (error) {
    if (!(error instanceof InvalidIssuerError)) throw error;
    throw new InvalidConfigError(`ISSUER: ${error.message}`);
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
  return { db: createD1Database(env.DB), issuer, keys };
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
