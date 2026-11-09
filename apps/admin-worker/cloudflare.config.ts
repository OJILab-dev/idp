// The admin Worker's deployment configuration, read by `cf deploy` (docs/design/deployment.md). Deployment-specific
// values are not written here: they come from the deploy script's environment, which takes them from the deployment
// settings file (the issuer, the admin host, the allowlist) and from a lookup by the database name (the D1 ID).
import { bindings, defineConfig, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";
// Package-export specifiers only: cf loads this file with Node's own loader (see src/settings.ts).
import { parseIssuer } from "@idp/core/shared/issuer";
import { parseAdminHost, parseAllowlist } from "@idp/admin-worker/settings";

/** The deploy script's environment; every value is untrusted until checked. */
export type DeployEnv = {
  readonly IDP_ISSUER?: string | undefined;
  readonly IDP_ADMIN_HOST?: string | undefined;
  /** The admin_allowlist of the deployment file as compact JSON. */
  readonly IDP_ADMIN_ALLOWLIST?: string | undefined;
  readonly IDP_D1_DATABASE_ID?: string | undefined;
};

const D1_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// The IdP Worker's name, a code constant shared with scripts/lib.sh and apps/worker/cloudflare.config.ts.
const IDP_WORKER_NAME = "idp";

// The IdP Worker's named entrypoint (apps/worker/src/internal.ts, declared in its exports). The default export is
// the public fetch handler, whose TLS and rate-limit checks refuse a binding call: it carries no request.cf and no
// client IP (docs/design/idpctl.md).
const IDP_INTERNAL_ENTRYPOINT = "IdpInternal";

/**
 * Builds the admin Worker's configuration from the deploy environment.
 *
 * Every value goes through the same parser the Worker runs at startup, so a value the Worker would refuse stops
 * the deploy instead of producing a Worker that refuses every request. The admin Worker holds no Secret: it binds
 * no signing key (docs/design/deployment.md, 署名鍵).
 *
 * @param env The deploy script's environment.
 * @returns The `worker` member of the configuration.
 * @throws {InvalidIssuerError} IDP_ISSUER is unset or not exactly `https://<host>`.
 * @throws {InvalidConfigError} IDP_ADMIN_HOST or IDP_ADMIN_ALLOWLIST is unset or malformed.
 * @throws {Error} IDP_D1_DATABASE_ID is unset or not a D1 database UUID.
 */
export function workerConfig(env: DeployEnv): CloudflareWorkerConfig {
  const issuer = parseIssuer(env.IDP_ISSUER);
  const adminHost = parseAdminHost(env.IDP_ADMIN_HOST, issuer);
  const allowlist = env.IDP_ADMIN_ALLOWLIST ?? "";
  parseAllowlist(env.IDP_ADMIN_ALLOWLIST);
  const d1Id = env.IDP_D1_DATABASE_ID;
  if (d1Id === undefined || !D1_ID.test(d1Id)) throw new Error("IDP_D1_DATABASE_ID is not a D1 database UUID");
  return {
    name: "idp-admin",
    compatibilityDate: "2026-10-01",
    entrypoint: "./src/index.ts",
    // The admin host is the only way in: it is the host where the edge enforces mTLS and the WAF rule (idpctl.md).
    domains: [{ hostname: adminHost, production: true, previews: false }],
    // workers.dev and preview URLs would reach the Worker without the edge mTLS check.
    workersDev: false,
    previewUrls: false,
    observability: {
      enabled: true,
      redactQueryString: true,
      // The Worker writes its own structured line per request; the automatic one would add request metadata.
      logs: { enabled: true, invocationLogs: false },
    },
    env: {
      DB: bindings.d1({ id: d1Id }),
      // Outbound only: the admin Worker reads the IdP Worker's discovery over RPC; nothing binds to the admin Worker.
      // The IdP Worker must be deployed first, so this entrypoint exists when the binding is created.
      IDP: bindings.worker({ worker: IDP_WORKER_NAME, exportName: IDP_INTERNAL_ENTRYPOINT }),
      ISSUER: bindings.text(issuer.url),
      ADMIN_HOST: bindings.text(adminHost),
      // Passed as reviewed, not re-serialised: the Worker parses the same text that the parser above accepted.
      ADMIN_ALLOWLIST: bindings.text(allowlist),
      CF_VERSION_METADATA: bindings.versionMetadata(),
    },
  };
}

export default defineConfig(() => ({ worker: workerConfig(process.env) }));
