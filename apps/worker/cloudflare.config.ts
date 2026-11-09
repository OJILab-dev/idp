// The IdP Worker's deployment configuration, read by `cf deploy` (docs/design/deployment.md). Deployment-specific
// values are not written here: the issuer and the D1 ID come from the deploy script's environment, which takes them
// from the deployment settings file (the issuer) and from a lookup by the database name (the D1 ID).
import { bindings, defineConfig, exports, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";
// Not "@idp/core/shared": cf loads this file with Node's own loader, which does not map the `.js` specifiers inside
// that index to `.ts` files. The issuer module has no imports of its own.
import { parseIssuer } from "@idp/core/shared/issuer";

/** The deploy script's environment; every value is untrusted until checked. */
export type DeployEnv = {
  readonly IDP_ISSUER?: string | undefined;
  readonly IDP_D1_DATABASE_ID?: string | undefined;
  /** rate_limit_namespace_id of the deployment settings file: unique within the account (deployment.md). */
  readonly IDP_RATE_LIMIT_NAMESPACE_ID?: string | undefined;
};

const D1_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// The same rule as infra/variables.tf rate_limit_namespace_id: a positive integer as a string.
const NAMESPACE_ID = /^[1-9][0-9]{0,17}$/;

/**
 * The Rate Limiting binding's period and limit. They match the provisional WAF rate limiting rule
 * (infra/main.tf) and are replaced together once a sign-in is measured (docs/design/open-questions.md).
 */
export const RATE_LIMIT = { period: 10, limit: 10 } as const;

/**
 * Builds the Worker's configuration from the deploy environment.
 *
 * The signing keys are Worker Secrets (SIGNING_KEY_ED25519_CURRENT, and when present SIGNING_KEY_ED25519_PREVIOUS,
 * SIGNING_KEY_RSA_CURRENT, SIGNING_KEY_RSA_PREVIOUS) registered by the Secret registration script. They are not
 * declared here: the first deploy runs before the key is registered (bootstrap stage 5 and 5b), and the Worker
 * itself refuses every request until a valid key is present.
 *
 * @param env The deploy script's environment.
 * @returns The `worker` member of the configuration.
 * @throws {InvalidIssuerError} IDP_ISSUER is unset or not exactly `https://<host>`.
 * @throws {Error} IDP_D1_DATABASE_ID is unset or not a D1 database UUID.
 * @throws {Error} IDP_RATE_LIMIT_NAMESPACE_ID is unset or not a positive integer.
 */
export function workerConfig(env: DeployEnv): CloudflareWorkerConfig {
  // The same parser as the Worker's, so the custom domain is exactly the host the Worker will accept.
  const issuer = parseIssuer(env.IDP_ISSUER);
  const d1Id = env.IDP_D1_DATABASE_ID;
  if (d1Id === undefined || !D1_ID.test(d1Id)) throw new Error("IDP_D1_DATABASE_ID is not a D1 database UUID");
  // No default: a guessed namespace could be one the service's Workers already count in, in the shared account.
  const namespace = env.IDP_RATE_LIMIT_NAMESPACE_ID;
  if (namespace === undefined || !NAMESPACE_ID.test(namespace)) throw new Error("IDP_RATE_LIMIT_NAMESPACE_ID is not a positive integer");
  return {
    name: "idp",
    compatibilityDate: "2026-10-01",
    entrypoint: "./src/index.ts",
    domains: [{ hostname: issuer.rpId, production: true, previews: false }],
    // The admin Worker's IDP Service Binding targets this named entrypoint (src/internal.ts), never the public
    // fetch handler, whose TLS and rate-limit checks refuse a binding call.
    exports: { IdpInternal: exports.worker() },
    // The custom domain is the only way in: the issuer, RP ID, and origin are all that host.
    workersDev: false,
    previewUrls: false,
    assets: {
      htmlHandling: "auto-trailing-slash",
      notFoundHandling: "none",
      // The pages stay pure assets, which are free and outside the daily request limit (free-tier.md).
      runWorkerFirst: false,
    },
    observability: {
      enabled: true,
      // /authorize carries id_token_hint, state, and nonce in its query; Workers Logs must not see them.
      redactQueryString: true,
      // The Worker writes its own structured line per request; the automatic one would add request metadata.
      logs: { enabled: true, invocationLogs: false },
    },
    env: {
      DB: bindings.d1({ id: d1Id }),
      ISSUER: bindings.text(issuer.url),
      // The Worker refuses every request without it: the audit rows of the user's own passkey operations need it.
      CF_VERSION_METADATA: bindings.versionMetadata(),
      // The Worker refuses every request without it (docs/design/free-tier.md).
      RATE_LIMITER: bindings.rateLimit({ namespace, simple: { limit: RATE_LIMIT.limit, period: RATE_LIMIT.period } }),
    },
  };
}

export default defineConfig(() => ({ worker: workerConfig(process.env) }));
