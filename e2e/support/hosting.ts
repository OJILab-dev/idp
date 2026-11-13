// The hosting mode the suite runs in (docs/design/hosting-modes.md 1). `pnpm run e2e` runs the whole suite once per
// mode, so every scenario is checked against both host shapes a deployment can have; E2E_HOSTING_MODE picks the run.
// The hosts are only names: Chromium maps them to the local servers (support/fixtures.ts), and nothing resolves them.
import { ADMIN_WORKER_NAME, IDP_WORKER_NAME, checkHostingHosts, parseHostingMode, type HostingMode } from "../../packages/core/src/hosting/index.js";

/**
 * The workers.dev subdomain of the account the workers_dev run stands in for. Any one DNS label would do; this one is
 * not an account the project owns.
 */
const WORKERS_DEV_SUBDOMAIN = "e2e-fork";

/** The hosts of one run. */
export type E2eHosting = {
  readonly mode: HostingMode;
  /** The issuer host, which is also the RP ID. */
  readonly idpHost: string;
  readonly adminHost: string;
  /**
   * A host on the issuer's registrable domain that neither Worker serves: in workers_dev another Worker of the same
   * account (same-site, hosting-modes.md 2.2), in custom_domain another host of the zone.
   */
  readonly neighbourHost: string;
};

/**
 * Derives the hosts of a run from the mode, the way a deployment derives them (hosting-modes.md 1.3): in workers_dev
 * from the Worker names and the account's subdomain, in custom_domain from fixed test names.
 *
 * @param value E2E_HOSTING_MODE; unset means custom_domain, so a plain `playwright test` keeps the original run.
 * @returns The run's hosts, already checked against the mode's rules.
 * @throws {InvalidHostingError} The value is set but is not a hosting mode.
 */
export function e2eHosting(value: string | undefined): E2eHosting {
  const mode = parseHostingMode(value ?? "custom_domain");
  const hosting: E2eHosting =
    mode === "workers_dev"
      ? {
          mode,
          idpHost: `${IDP_WORKER_NAME}.${WORKERS_DEV_SUBDOMAIN}.workers.dev`,
          adminHost: `${ADMIN_WORKER_NAME}.${WORKERS_DEV_SUBDOMAIN}.workers.dev`,
          neighbourHost: `another-worker.${WORKERS_DEV_SUBDOMAIN}.workers.dev`,
        }
      : { mode, idpHost: "idp.test", adminHost: "admin.idp.test", neighbourHost: "www.idp.test" };
  // The same rule both Workers apply at start, so a run whose hosts the deployment would refuse fails here first.
  checkHostingHosts(mode, hosting.idpHost, hosting.adminHost);
  return hosting;
}

/** The hosts of this run; Playwright's worker processes inherit E2E_HOSTING_MODE from the runner. */
export const HOSTING = e2eHosting(process.env["E2E_HOSTING_MODE"]);
