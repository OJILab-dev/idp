// The Playwright fixtures every scenario uses: one local IdP and RP stand-in per worker process, a browser that
// reaches both at production-shaped https hosts, and per test a tab with virtual authenticators and a CSP check.
import { join } from "node:path";
import { test as base, expect, type Page } from "@playwright/test";
import { en } from "../../apps/worker/pages/locales/en.js";
import { virtualAuthenticators, type Authenticators, type VirtualCredential } from "./authenticator.js";
import { OUTPUT_DIR } from "./build.js";
import { HOSTING } from "./hosting.js";
import { IDP_HOST, startIdp, type LocalIdp } from "./idp.js";
import { RP_HOST, startRp, type LocalRp } from "./rp.js";
import { adminFor, type Admin } from "./seed.js";
import { generateCertificate } from "./tls.js";

type WorkerFixtures = {
  readonly idp: LocalIdp;
  readonly rp: LocalRp;
};

type TestFixtures = {
  readonly admin: Admin;
  readonly authenticators: Authenticators;
  /** Every CSP violation the test's pages reported; the test fails unless it stays empty. */
  readonly cspViolations: readonly string[];
};

export const test = base.extend<TestFixtures, WorkerFixtures>({
  idp: [
    // eslint-disable-next-line no-empty-pattern -- Playwright reads the dependencies from a destructuring pattern.
    async ({}, use, workerInfo) => {
      const certificate = await generateCertificate([IDP_HOST, RP_HOST, HOSTING.neighbourHost], join(OUTPUT_DIR, `tls-${workerInfo.workerIndex}`));
      const idp = await startIdp(certificate);
      await use(idp);
      await idp.dispose();
    },
    { scope: "worker", timeout: 60_000 },
  ],
  rp: [
    async ({ idp }, use) => {
      const rp = await startRp(idp.certificate);
      await use(rp);
      await rp.close();
    },
    { scope: "worker" },
  ],
  // The issuer is https://<the run's issuer host> on port 443 (support/hosting.ts): Chromium maps that host and port (and the RP's) to the local servers
  // and trusts the run's certificate by its key alone, so the pages are secure contexts without certificate errors,
  // which WebAuthn requires. No production check is relaxed: the Worker still sees https and its own issuer host.
  // The neighbour host (support/hosting.ts) reaches the IdP's server too, as a re-enabled route would, so a test can
  // see which cookies the browser sends there and that the Worker refuses the host.
  launchOptions: [
    async ({ idp, rp }, use) => {
      const rules = [`MAP ${IDP_HOST}:443 127.0.0.1:${idp.port}`, `MAP ${RP_HOST}:443 127.0.0.1:${rp.port}`, `MAP ${HOSTING.neighbourHost}:443 127.0.0.1:${idp.port}`];
      await use({
        args: [
          `--host-resolver-rules=${rules.join(", ")}`,
          `--ignore-certificate-errors-spki-list=${idp.certificate.spkiSha256}`,
        ],
      });
    },
    { scope: "worker" },
  ],
  admin: async ({ idp }, use) => {
    await use(adminFor(idp.db));
  },
  authenticators: async ({ page }, use) => {
    await use(await virtualAuthenticators(page));
  },
  // Chromium reports every blocked load or execution as a console error naming the Content Security Policy; the
  // detection itself is checked by the CSP scenario.
  cspViolations: [
    async ({ page }, use) => {
      const violations: string[] = [];
      page.on("console", (message) => {
        if (/Content Security Policy/i.test(message.text())) violations.push(message.text());
      });
      await use(violations);
      expect(violations, "CSP violations").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/**
 * Registers a passkey through an enroll link, as the user would on first use.
 *
 * @param page The tab, with an authenticator attached.
 * @param enrollLink The link from enroll_link_issue.
 * @throws {Error} The page does not report success.
 */
export async function enroll(page: Page, enrollLink: string): Promise<void> {
  await page.goto(enrollLink);
  await page.getByRole("button", { name: en.enroll_button }).click();
  await expect(page.getByRole("status")).toHaveText(en.enroll_done);
}

/**
 * Takes an authenticator away, keeping its credentials, as a user putting the phone down would. With none attached
 * the sign-in page's conditional request has nothing to complete with, so the page stays put.
 *
 * @returns The credentials it held.
 * @throws {Error} The CDP calls fail.
 */
export async function detach(authenticators: Authenticators, authenticatorId: string): Promise<readonly VirtualCredential[]> {
  const credentials = await authenticators.credentials(authenticatorId);
  await authenticators.remove(authenticatorId);
  return credentials;
}

/**
 * Attaches a new authenticator holding the credentials.
 *
 * @returns Its authenticator ID.
 * @throws {Error} The CDP calls fail.
 */
export async function attach(authenticators: Authenticators, credentials: readonly VirtualCredential[]): Promise<string> {
  const authenticatorId = await authenticators.add();
  for (const credential of credentials) await authenticators.addCredential(authenticatorId, credential);
  return authenticatorId;
}

// How long a pending conditional request gets to complete on its own after the authenticator returns. The virtual
// authenticator answers within milliseconds, so a request that would complete does so well inside this.
const CONDITIONAL_GRACE_MS = 1_000;

/**
 * Signs in on the sign-in page with the button, after the page loaded with no authenticator attached. It proves the
 * button did the work: re-attaching the passkey alone sends no /webauthn/auth/verify and leaves the tab on /signin,
 * and the verify request follows the click.
 *
 * @param credentials The passkeys {@link detach} took away; attached again before the click.
 * @throws {Error} The page signs in before the click, or not after it.
 */
export async function signInWithButton(page: Page, authenticators: Authenticators, credentials: readonly VirtualCredential[]): Promise<void> {
  await expectSignInPage(page);
  const verifies: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/webauthn/auth/verify") verifies.push(request.url());
  });
  await attach(authenticators, credentials);
  await page.waitForTimeout(CONDITIONAL_GRACE_MS);
  expect(verifies, "a sign-in before the click").toEqual([]);
  await expectSignInPage(page);

  const verify = page.waitForRequest((request) => new URL(request.url()).pathname === "/webauthn/auth/verify");
  await page.getByRole("button", { name: en.signin_button }).click();
  await verify;
}

/**
 * Asserts the tab shows the sign-in page, ready for the button.
 *
 * @throws {Error} The tab is elsewhere.
 */
export async function expectSignInPage(page: Page): Promise<void> {
  await expect(page).toHaveURL((url) => url.origin === `https://${IDP_HOST}` && url.pathname === "/signin");
  await expect(page.getByRole("button", { name: en.signin_button })).toBeEnabled();
}
