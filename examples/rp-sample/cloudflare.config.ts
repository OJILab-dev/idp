// The sample RP's deployment configuration, read by `cf build` and `cf deploy` (never wrangler). The deployment's
// values come from the environment that scripts/deploy-rp-sample.sh sets; nothing deployment-specific is written here,
// and nothing secret: CLIENT_SECRET and SESSION_KEY are Worker Secrets set by scripts/set-rp-sample-secrets.sh.
//
// Self-contained on purpose: cf evaluates this file with Node's own loader, and the sample imports nothing from the
// IdP's packages, so the checks below repeat the Worker's (src/config.ts), which checks again at run time.
import { bindings, defineConfig, type WorkerConfig as CloudflareWorkerConfig } from "cf/config";

/** The Worker's name, and so the first label of its workers.dev host. Keep in sync with scripts/lib.sh. */
export const RP_SAMPLE_WORKER_NAME = "rp-sample";

/** The deploy script's environment; every value is untrusted until checked. */
export type DeployEnv = {
  /** The IdP's issuer, `https://idp.<workers_dev_subdomain>.workers.dev` for the easyidp deployment. */
  readonly RP_SAMPLE_ISSUER?: string | undefined;
  /** The client_id registered with `idpctl client_create`. */
  readonly RP_SAMPLE_CLIENT_ID?: string | undefined;
  /** This Worker's origin, `https://rp-sample.<workers_dev_subdomain>.workers.dev`. */
  readonly RP_SAMPLE_ORIGIN?: string | undefined;
};

const HTTPS_ORIGIN = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;
const CLIENT_ID = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const OWN_ORIGIN = new RegExp(`^https://${RP_SAMPLE_WORKER_NAME}\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.workers\\.dev$`);

/**
 * Builds the Worker's configuration from the deploy environment.
 *
 * @param env The deploy script's environment.
 * @returns The `worker` member of the configuration.
 * @throws {Error} RP_SAMPLE_ISSUER is not an https origin (the IdP's issuers are origins).
 * @throws {Error} RP_SAMPLE_CLIENT_ID is not a client_id the IdP accepts.
 * @throws {Error} RP_SAMPLE_ORIGIN is not this Worker's workers.dev origin.
 */
export function workerConfig(env: DeployEnv): CloudflareWorkerConfig {
  const issuer = env.RP_SAMPLE_ISSUER;
  if (issuer === undefined || !HTTPS_ORIGIN.test(issuer)) throw new Error("RP_SAMPLE_ISSUER is not an https origin");
  const clientId = env.RP_SAMPLE_CLIENT_ID;
  if (clientId === undefined || !CLIENT_ID.test(clientId)) throw new Error("RP_SAMPLE_CLIENT_ID is not a client_id");
  const origin = env.RP_SAMPLE_ORIGIN;
  if (origin === undefined || !OWN_ORIGIN.test(origin)) throw new Error(`RP_SAMPLE_ORIGIN is not https://${RP_SAMPLE_WORKER_NAME}.<subdomain>.workers.dev`);
  return {
    name: RP_SAMPLE_WORKER_NAME,
    compatibilityDate: "2026-10-01",
    // Without it, a fetch from this Worker to a workers.dev host of the same account, the IdP's in the easyidp
    // deployment, fails and every sign-in answers 502 (observed on the first deploy). The flag sends the fetch over the
    // public Internet, as from a third-party RP: the IdP rate-limits by its CF-Connecting-IP and checks its TLS version.
    // Not a service binding: that would bypass both and tie this reference RP to the IdP's account.
    compatibilityFlags: ["global_fetch_strictly_public"],
    entrypoint: "./src/index.ts",
    // workers.dev only: the redirect URI registered with the IdP is on this host, and preview URLs would be other
    // hosts the Worker refuses anyway.
    workersDev: true,
    previewUrls: false,
    observability: {
      enabled: true,
      // The callback's query carries the code and state; Workers Logs must not see them.
      redactQueryString: true,
      logs: { enabled: true, invocationLogs: false },
    },
    // The secrets are not declared here: the first deploy runs before they are set, and the Worker refuses every
    // request until both are present (src/config.ts).
    env: {
      ISSUER: bindings.text(issuer),
      CLIENT_ID: bindings.text(clientId),
      ORIGIN: bindings.text(origin),
    },
  };
}

export default defineConfig(() => ({ worker: workerConfig(process.env) }));
