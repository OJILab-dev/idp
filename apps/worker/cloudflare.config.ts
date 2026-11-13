// The IdP Worker's deployment configuration, read by `cf deploy` (docs/design/deployment.md). Deployment-specific
// values are not written here: the hosting mode, the issuer, and the D1 ID come from the deploy script's environment,
// which takes them from the deployment settings file (the mode, and the issuer it derives from issuer_host or
// workers_dev_subdomain) and from a lookup by the database name (the D1 ID).
import { bindings, defineConfig, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";
// @idp/hosting and @idp/issuer point straight at their modules, not at an index: cf evaluates this file with
// Node's own loader, which does not map an index's `.js` specifiers to `.ts`. Both modules import nothing themselves.
import { IDP_WORKER_NAME, checkHostingHosts, parseHostingMode } from "@idp/hosting";
import { parseIssuer } from "@idp/issuer";

/** The deploy script's environment; every value is untrusted until checked. */
export type DeployEnv = {
  /** hosting_mode of the deployment settings file (docs/design/hosting-modes.md 1.1). */
  readonly IDP_HOSTING_MODE?: string | undefined;
  /** `https://<issuer_host>`, or `https://idp.<workers_dev_subdomain>.workers.dev` (hosting-modes.md 1.3). */
  readonly IDP_ISSUER?: string | undefined;
  readonly IDP_D1_DATABASE_ID?: string | undefined;
  /** rate_limit_namespace_id of the deployment settings file: unique within the account (deployment.md). */
  readonly IDP_RATE_LIMIT_NAMESPACE_ID?: string | undefined;
  /** rs256_enabled of the deployment settings file, `true` or `false` (docs/design/tokens.md, "署名鍵"). */
  readonly IDP_RS256_ENABLED?: string | undefined;
};

const D1_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// The same rule as infra/variables.tf rate_limit_namespace_id: a positive integer as a string.
const NAMESPACE_ID = /^[1-9][0-9]{0,17}$/;

/**
 * The Rate Limiting binding's period and limit, the only rate limit of the IdP (no WAF rule; docs/design/free-tier.md).
 * Provisional: replaced once a sign-in is measured (docs/design/open-questions.md).
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
 * The mode decides where the Worker is served (docs/design/hosting-modes.md 1.2): custom_domain serves the issuer host
 * as a custom domain with workers.dev off; workers_dev serves the workers.dev route only, with no custom domain.
 * Preview URLs are off in both.
 *
 * @param env The deploy script's environment.
 * @returns The `worker` member of the configuration.
 * @throws {InvalidHostingError} IDP_HOSTING_MODE is unset or unknown, or the issuer host does not match the mode.
 * @throws {InvalidIssuerError} IDP_ISSUER is unset or not exactly `https://<host>`.
 * @throws {Error} IDP_D1_DATABASE_ID is unset or not a D1 database UUID.
 * @throws {Error} IDP_RATE_LIMIT_NAMESPACE_ID is unset or not a positive integer.
 * @throws {Error} IDP_RS256_ENABLED is neither `true` nor `false`.
 */
export function workerConfig(env: DeployEnv): CloudflareWorkerConfig {
  const mode = parseHostingMode(env.IDP_HOSTING_MODE);
  // The same parsers as the Worker's, so the route is exactly the host the Worker will accept.
  const issuer = parseIssuer(env.IDP_ISSUER);
  checkHostingHosts(mode, issuer.rpId);
  const d1Id = env.IDP_D1_DATABASE_ID;
  if (d1Id === undefined || !D1_ID.test(d1Id)) throw new Error("IDP_D1_DATABASE_ID is not a D1 database UUID");
  // No default: a guessed namespace could be one the service's Workers already count in, in the shared account.
  const namespace = env.IDP_RATE_LIMIT_NAMESPACE_ID;
  if (namespace === undefined || !NAMESPACE_ID.test(namespace)) throw new Error("IDP_RATE_LIMIT_NAMESPACE_ID is not a positive integer");
  // No default: whether RS256 is offered is the operator's explicit choice, written in the deployment file.
  const rs256 = env.IDP_RS256_ENABLED;
  if (rs256 !== "true" && rs256 !== "false") throw new Error("IDP_RS256_ENABLED must be true or false");
  return {
    // In the workers_dev mode the name is the issuer host's first label, so it is the shared-core constant.
    name: IDP_WORKER_NAME,
    compatibilityDate: "2026-10-01",
    entrypoint: "./src/index.ts",
    ...(mode === "custom_domain" ? { domains: [{ hostname: issuer.rpId, production: true, previews: false }] } : {}),
    // One way in per mode, the issuer host: the custom domain, or the workers.dev route. The issuer, RP ID, and origin
    // are all that host, and preview URLs would be other hosts the Worker refuses anyway (hosting-modes.md 1.2).
    workersDev: mode === "workers_dev",
    previewUrls: false,
    assets: {
      htmlHandling: "auto-trailing-slash",
      notFoundHandling: "none",
      // Every request runs the Worker first, the pages included: no zone rule redirects plain http or enforces
      // TLS 1.2 on the issuer host, so the Worker must see every request to do both. The pages then count against
      // the daily request limit (docs/design/free-tier.md; docs/design/domain-placement.md, 3).
      runWorkerFirst: true,
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
      // Checked again by the Worker at start against the issuer (hosting-modes.md 1.4).
      HOSTING_MODE: bindings.text(mode),
      // The source of truth for RS256: `true` makes the Worker require the RSA key Secret, `false` ignores it.
      RS256_ENABLED: bindings.text(rs256),
      // The Worker refuses every request without it: the audit rows of the user's own passkey operations need it.
      CF_VERSION_METADATA: bindings.versionMetadata(),
      // The Worker refuses every request without it (docs/design/free-tier.md).
      // The Worker serves the pages through it; it refuses every request without it.
      ASSETS: bindings.assets(),
      RATE_LIMITER: bindings.rateLimit({ namespace, simple: { limit: RATE_LIMIT.limit, period: RATE_LIMIT.period } }),
    },
  };
}

export default defineConfig(() => ({ worker: workerConfig(process.env) }));
