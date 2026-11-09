// The IdP Worker's deployment configuration, read by `cf deploy` (docs/design/deployment.md). Deployment-specific
// values are not written here: the issuer and the D1 ID come from the deploy script's environment, which takes them
// from the deployment settings file (the issuer) and from a lookup by the database name (the D1 ID).
import { bindings, defineConfig, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";
// Not "@idp/core/shared": cf loads this file with Node's own loader, which does not map the `.js` specifiers inside
// that index to `.ts` files. The issuer module has no imports of its own.
import { parseIssuer } from "@idp/core/shared/issuer";

/** The deploy script's environment; every value is untrusted until checked. */
export type DeployEnv = {
  readonly IDP_ISSUER?: string | undefined;
  readonly IDP_D1_DATABASE_ID?: string | undefined;
};

const D1_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

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
 */
export function workerConfig(env: DeployEnv): CloudflareWorkerConfig {
  // The same parser as the Worker's, so the custom domain is exactly the host the Worker will accept.
  const issuer = parseIssuer(env.IDP_ISSUER);
  const d1Id = env.IDP_D1_DATABASE_ID;
  if (d1Id === undefined || !D1_ID.test(d1Id)) throw new Error("IDP_D1_DATABASE_ID is not a D1 database UUID");
  return {
    name: "idp",
    compatibilityDate: "2026-10-01",
    entrypoint: "./src/index.ts",
    domains: [{ hostname: issuer.rpId, production: true, previews: false }],
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
    },
  };
}

export default defineConfig(() => ({ worker: workerConfig(process.env) }));
