// The hosting modes (docs/design/hosting-modes.md 1). The mode decides nothing at run time: both Workers serve the
// same code in both modes. It exists so that a configuration mixing the modes (a workers.dev issuer in the
// custom_domain mode, a custom admin host in the workers_dev mode) is refused wherever it is read (1.4).

/** The two hosting modes; a deployment names one and has no default (1.1). */
export const HOSTING_MODES = ["custom_domain", "workers_dev"] as const;

/** A hosting mode. */
export type HostingMode = (typeof HOSTING_MODES)[number];

/**
 * The IdP Worker's name. In the workers_dev mode it is the issuer host's first label, so changing it changes the
 * issuer (1.2); it is code, not a deployment input.
 */
export const IDP_WORKER_NAME = "idp";

/** The admin Worker's name, the admin host's first label in the workers_dev mode (1.3). */
export const ADMIN_WORKER_NAME = "idp-admin";

/** Thrown when the hosting mode or a host does not match the rules of the mode. */
export class InvalidHostingError extends Error {
  override readonly name = "InvalidHostingError";
}

// One DNS label of the account's workers.dev subdomain (1.1): lowercase letters, digits, and hyphens, 1 to 63
// characters, neither starting nor ending with a hyphen.
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const WORKERS_DEV_ISSUER = new RegExp(`^${IDP_WORKER_NAME}\\.(${LABEL})\\.workers\\.dev$`);

/**
 * Parses a hosting mode exactly as written.
 *
 * @param value The untrusted value, such as the `HOSTING_MODE` variable.
 * @returns The mode.
 * @throws {InvalidHostingError} The value is missing or is not exactly one of {@link HOSTING_MODES}.
 */
export function parseHostingMode(value: unknown): HostingMode {
  if (typeof value !== "string" || !(HOSTING_MODES as readonly string[]).includes(value)) {
    throw new InvalidHostingError("the hosting mode must be custom_domain or workers_dev");
  }
  return value as HostingMode;
}

function isUnderWorkersDev(host: string): boolean {
  return host === "workers.dev" || host.endsWith(".workers.dev");
}

/**
 * Checks that the hosts have the form the mode requires (docs/design/hosting-modes.md 1.3, 1.4).
 *
 * In custom_domain, no host may be workers.dev or under it. In workers_dev, the issuer host must be
 * `idp.<subdomain>.workers.dev` with one DNS label as the subdomain, and the admin host must be
 * `idp-admin.<the same subdomain>.workers.dev`.
 *
 * @param mode The hosting mode.
 * @param issuerHost The issuer's host, already canonical (lowercase, no port).
 * @param adminHost The admin host, already canonical; omitted by the IdP Worker, which has none.
 * @throws {InvalidHostingError} A host does not match the mode.
 */
export function checkHostingHosts(mode: HostingMode, issuerHost: string, adminHost?: string): void {
  const hosts = adminHost === undefined ? [issuerHost] : [issuerHost, adminHost];
  if (mode === "custom_domain") {
    if (hosts.some(isUnderWorkersDev)) throw new InvalidHostingError("custom_domain hosts must not be under workers.dev");
    return;
  }
  const subdomain = WORKERS_DEV_ISSUER.exec(issuerHost)?.[1];
  if (subdomain === undefined) throw new InvalidHostingError(`the workers_dev issuer host must be ${IDP_WORKER_NAME}.<subdomain>.workers.dev`);
  if (adminHost !== undefined && adminHost !== `${ADMIN_WORKER_NAME}.${subdomain}.workers.dev`) {
    throw new InvalidHostingError(`the workers_dev admin host must be ${ADMIN_WORKER_NAME}.<the issuer's subdomain>.workers.dev`);
  }
}
