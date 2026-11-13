// Scenario 8: every page the IdP serves is under the strict CSP and runs without a single violation
// (security-checklist.md; _headers for the static pages, the Worker's headers for the error page). The fixture fails
// any test whose pages report a violation; this one visits each page on purpose and checks the policy is enforced.
import type { Response } from "@playwright/test";
import { expect, expectSignInPage, test } from "../support/fixtures.js";
import { ISSUER } from "../support/idp.js";
import { authorizeFlow } from "../support/rp.js";
import type { SeededClient } from "../support/seed.js";

const POLICY = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

async function expectStrictHeaders(response: Response | null): Promise<void> {
  if (response === null) throw new Error("no document was loaded");
  expect(await response.headerValues("content-security-policy")).toEqual([POLICY]);
  expect(await response.headerValues("x-frame-options")).toEqual(["DENY"]);
  expect(await response.headerValues("referrer-policy")).toEqual(["no-referrer"]);
  // _headers sets it under both /* and the page's own rule, so a page carries it twice; every copy must agree.
  const nosniff = await response.headerValues("x-content-type-options");
  expect(nosniff.length).toBeGreaterThan(0);
  expect(nosniff.every((value) => value === "nosniff")).toBe(true);
}

// The headers come from the shipped _headers through workerd's real asset server, which the unit tests replace with
// a stand-in (apps/worker/test/pages.test.ts reads only the file).
test("the sign-in, enrollment, account, and error pages load under the CSP with no violation", async ({ page, admin }) => {
  const user = await admin.createUser("Alice");
  const client = await admin.createClient("confidential", user.userId);

  // With no authenticator attached, the pages stay up instead of completing a ceremony.
  await expectStrictHeaders(await page.goto(user.enrollLink));

  // The 303 to /signin is followed; the page's own response carries the asset headers.
  const signin = page.waitForResponse((response) => new URL(response.url()).pathname === "/signin");
  await page.goto(authorizeFlow(client).url);
  await expectStrictHeaders(await signin);
  await expectSignInPage(page);

  await expectStrictHeaders(await page.goto(`${ISSUER}/account`));

  const unknown: SeededClient = { clientId: "no-such-client", type: "confidential" };
  await expectStrictHeaders(await page.goto(authorizeFlow(unknown).url));
});

test("the policy is enforced: an injected inline script is blocked and reported", async ({ browser }) => {
  // A tab of its own, outside the fixture that fails on violations, to show the detection itself works.
  const context = await browser.newContext();
  const page = await context.newPage();
  const messages: string[] = [];
  page.on("console", (message) => messages.push(message.text()));
  await page.goto(`${ISSUER}/enroll`);
  // Page-side code as a string: the e2e code is typed for Node and workerd, not the DOM.
  const ran = await page.evaluate(`(() => {
    const script = document.createElement("script");
    script.textContent = "document.body.dataset.injected = 'yes'";
    document.body.append(script);
    return document.body.dataset.injected ?? "no";
  })()`);
  expect(ran).toBe("no");
  await expect.poll(() => messages.some((text) => /Content Security Policy/.test(text))).toBe(true);
  await context.close();
});
