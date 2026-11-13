// Scenario 3: prompt=login, and every public client, require a fresh passkey sign-in even with a live session
// (authentication.md, steps 2 and 4).
import type { Page } from "@playwright/test";
import { detach, expect, signInWithButton, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { IDP_HOST } from "../support/idp.js";
import { authorizeFlow } from "../support/rp.js";

/** Records the paths of the IdP documents the tab loads. */
function idpDocuments(page: Page): string[] {
  const paths: string[] = [];
  page.on("framenavigated", (frame) => {
    const url = new URL(frame.url());
    if (frame === page.mainFrame() && url.hostname === IDP_HOST) paths.push(url.pathname);
  });
  return paths;
}

test("prompt=login and a public client each ask for the passkey again although the session is live", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  const publicClient = await admin.createClient("public", user.userId);
  const first = authorizeFlow(client);
  await page.goto(first.url);
  await finishCodeFlow(page, idp, client, first);

  // With the session, a plain request is answered with a code at once.
  const documents = idpDocuments(page);
  const silent = authorizeFlow(client);
  await page.goto(silent.url);
  await finishCodeFlow(page, idp, client, silent);
  expect(documents).not.toContain("/signin");

  const passkeys = await detach(authenticators, user.authenticatorId);
  const login = authorizeFlow(client, { prompt: "login" });
  await page.goto(login.url);
  const holder = await signInWithButton(page, authenticators, passkeys);
  await finishCodeFlow(page, idp, client, login);

  // A public client asks again too, even right after a fresh sign-in.
  const again = await detach(authenticators, holder);
  const flow = authorizeFlow(publicClient);
  await page.goto(flow.url);
  await signInWithButton(page, authenticators, again);
  await finishCodeFlow(page, idp, publicClient, flow);
});
