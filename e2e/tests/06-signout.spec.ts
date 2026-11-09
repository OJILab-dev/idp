// Scenario 6: signing out on the account page ends the session, so the next /authorize asks for the passkey again
// (authentication.md, "サインアウト").
import { en } from "../../apps/worker/pages/locales/en.js";
import { detach, expect, signInWithButton, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { IDP_HOST, ISSUER } from "../support/idp.js";
import { authorizeFlow } from "../support/rp.js";

test("sign-out clears the session and the next authorization request needs a sign-in", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await finishCodeFlow(page, idp, client, flow);

  await page.goto(`${ISSUER}/account`);
  await page.getByRole("button", { name: en.account_logout }).click();
  await expect(page.getByRole("status")).toHaveText(en.account_signed_out);
  expect(await page.context().cookies(`https://${IDP_HOST}`)).toEqual([]);
  const sessions = await idp.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(user.userId).first();
  expect(sessions).toEqual({ n: 0 });

  const passkeys = await detach(authenticators, user.authenticatorId);
  const next = authorizeFlow(client);
  await page.goto(next.url);
  await signInWithButton(page, authenticators, passkeys);
  await finishCodeFlow(page, idp, client, next);
});
