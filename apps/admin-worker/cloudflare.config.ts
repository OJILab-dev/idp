// The admin Worker's deployment configuration, read by `cf deploy` (docs/design/deployment.md). Deployment-specific
// values are not written here: they come from the deploy script's environment, which takes them from the deployment
// settings file (the hosting mode, the hosts, the namespace ID, admin_signing_keys) and from a lookup by the
// database name (the D1 ID). Every value is checked here, and the Worker checks them again at start.
import { bindings, defineConfig, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";
// Through the per-module exports, not "@idp/core/shared": cf evaluates this file with Node's own loader, which does
// not map the index's `.js` specifiers to `.ts`. Both modules import nothing themselves.
import { ADMIN_WORKER_NAME, IDP_WORKER_NAME, checkHostingHosts, parseHostingMode } from "@idp/core/shared/hosting";
import { parseIssuer } from "@idp/core/shared/issuer";

/** The deploy script's environment; every value is untrusted until checked. */
export type AdminDeployEnv = {
  /** hosting_mode of the deployment settings file (docs/design/hosting-modes.md 1.1). */
  readonly IDP_HOSTING_MODE?: string | undefined;
  readonly IDP_ISSUER?: string | undefined;
  readonly IDP_ADMIN_HOST?: string | undefined;
  readonly IDP_D1_DATABASE_ID?: string | undefined;
  /** admin_rate_limit_namespace_id of the deployment settings file (hosting-modes.md 6.2). */
  readonly IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID?: string | undefined;
  /** admin_signing_keys of the deployment settings file, as a JSON array (hosting-modes.md 3.7). */
  readonly IDP_ADMIN_SIGNING_KEYS?: string | undefined;
};

const D1_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// The same rule as infra/variables.tf admin_rate_limit_namespace_id: a positive integer as a string.
const NAMESPACE_ID = /^[1-9][0-9]{0,17}$/;

/**
 * The admin Worker's Rate Limiting binding's period and limit (docs/design/hosting-modes.md 6.2). Provisional:
 * idpctl sends one request per run (three with its retries), so a run of operations stays under it; replaced once
 * measured (docs/design/open-questions.md).
 */
export const ADMIN_RATE_LIMIT = { period: 10, limit: 10 } as const;

function signingKeys(value: string | undefined): string {
  // The shape only: the Worker imports each key and checks its keyid at start, and refuses every request otherwise.
  // An empty list is refused here too, so a deployment that would lock every admin out does not even build.
  let rows: unknown;
  try {
    rows = JSON.parse(value ?? "");
  } catch {
    throw new Error("IDP_ADMIN_SIGNING_KEYS is not JSON");
  }
  const valid =
    Array.isArray(rows) &&
    rows.length > 0 &&
    rows.every((row: unknown) => {
      if (typeof row !== "object" || row === null || Array.isArray(row)) return false;
      const keys = Object.keys(row).sort();
      return keys.join(",") === "keyid,name,public_key" && keys.every((k) => typeof (row as Record<string, unknown>)[k] === "string");
    });
  if (!valid) throw new Error("IDP_ADMIN_SIGNING_KEYS must be a non-empty array of {keyid, name, public_key}");
  return value as string;
}

/**
 * Builds the admin Worker's configuration from the deploy environment.
 *
 * The mode decides where the Worker is served (docs/design/hosting-modes.md 1.2): custom_domain serves the admin host
 * as a custom domain with workers.dev off; workers_dev serves the workers.dev route only. Preview URLs are off in
 * both. The Worker has no Secret: the allowlist holds public keys only.
 *
 * @param env The deploy script's environment.
 * @returns The `worker` member of the configuration.
 * @throws {InvalidHostingError} IDP_HOSTING_MODE is unset or unknown, or a host does not match the mode.
 * @throws {InvalidIssuerError} IDP_ISSUER is unset or not exactly `https://<host>`.
 * @throws {Error} IDP_ADMIN_HOST is not a canonical host or equals the issuer host; IDP_D1_DATABASE_ID is not a D1
 *   database UUID; IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID is not a positive integer; or IDP_ADMIN_SIGNING_KEYS is not a
 *   non-empty array of rows of exactly keyid, name, and public_key.
 */
export function adminWorkerConfig(env: AdminDeployEnv): CloudflareWorkerConfig {
  const mode = parseHostingMode(env.IDP_HOSTING_MODE);
  // The same parsers as the Worker's, so the route is exactly the host the Worker will accept.
  const issuer = parseIssuer(env.IDP_ISSUER);
  const adminHost = parseIssuer(`https://${env.IDP_ADMIN_HOST ?? ""}`).rpId;
  if (env.IDP_ADMIN_HOST !== adminHost) throw new Error("IDP_ADMIN_HOST must be a canonical hostname");
  if (adminHost === issuer.rpId) throw new Error("IDP_ADMIN_HOST must differ from the issuer host");
  checkHostingHosts(mode, issuer.rpId, adminHost);
  const d1Id = env.IDP_D1_DATABASE_ID;
  if (d1Id === undefined || !D1_ID.test(d1Id)) throw new Error("IDP_D1_DATABASE_ID is not a D1 database UUID");
  // No default: a guessed namespace could be one the IdP Worker or the service's Workers already count in.
  const namespace = env.IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID;
  if (namespace === undefined || !NAMESPACE_ID.test(namespace)) throw new Error("IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID is not a positive integer");
  const allowlist = signingKeys(env.IDP_ADMIN_SIGNING_KEYS);
  return {
    name: ADMIN_WORKER_NAME,
    compatibilityDate: "2026-10-01",
    entrypoint: "./src/index.ts",
    ...(mode === "custom_domain" ? { domains: [{ hostname: adminHost, production: true, previews: false }] } : {}),
    workersDev: mode === "workers_dev",
    previewUrls: false,
    observability: {
      enabled: true,
      // Cursors and filters are not secret, but the query is not needed to investigate a failure.
      redactQueryString: true,
      // The Worker writes its own structured line per request; the automatic one would add request metadata.
      logs: { enabled: true, invocationLogs: false },
    },
    env: {
      DB: bindings.d1({ id: d1Id }),
      ISSUER: bindings.text(issuer.url),
      ADMIN_HOST: bindings.text(adminHost),
      HOSTING_MODE: bindings.text(mode),
      ADMIN_SIGNING_KEYS: bindings.text(allowlist),
      CF_VERSION_METADATA: bindings.versionMetadata(),
      // Counted per client IP before the signature is parsed; the Worker refuses every request without it.
      RATE_LIMITER: bindings.rateLimit({ namespace, simple: { limit: ADMIN_RATE_LIMIT.limit, period: ADMIN_RATE_LIMIT.period } }),
      IDP: bindings.worker({ worker: IDP_WORKER_NAME, exportName: "IdpInternal" }),
    },
  };
}

export default defineConfig(() => ({ worker: adminWorkerConfig(process.env) }));
