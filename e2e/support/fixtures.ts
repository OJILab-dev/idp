// The Playwright fixtures every scenario uses: one local IdP and RP stand-in per worker process, a browser that
// reaches both at production-shaped https hosts, and per test a tab with virtual authenticators and a CSP check.
import { join } from "node:path";
import { test as base, expect, type Page } from "@playwright/test";
import { en } from "../../apps/worker/pages/locales/en.js";
import { virtualAuthenticators, type Authenticators, type VirtualCredential } from "./authenticator.js";
import { OUTPUT_DIR } from "./build.js";
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
      const certificate = await generateCertificate([IDP_HOST, RP_HOST], join(OUTPUT_DIR, `tls-${workerInfo.workerIndex}`));
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
  // The issuer is https://idp.test on port 443: Chromium maps that host and port (and the RP's) to the local servers
  // and trusts the run's certificate by its key alone, so the pages are secure contexts without certificate errors,
  // which WebAuthn requires. No production check is relaxed: the Worker still sees https and its own issuer host.
  launchOptions: [
    async ({ idp, rp }, use) => {
      await use({
        args: [
          `--host-resolver-rules=MAP ${IDP_HOST}:443 127.0.0.1:${idp.port}, MAP ${RP_HOST}:443 127.0.0.1:${rp.port}`,
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

/**
 * Asserts the tab shows the sign-in page, ready for the button.
 *
 * @throws {Error} The tab is elsewhere.
 */
export async function expectSignInPage(page: Page): Promise<void> {
  await expect(page).toHaveURL((url) => url.origin === `https://${IDP_HOST}` && url.pathname === "/signin");
  await expect(page.getByRole("button", { name: en.signin_button })).toBeEnabled();
}
