// Scenario 7: a user disabled through the core's user_disable loses the session and cannot sign in again
// (authentication.md, "無効化されたユーザー").
import { en } from "../../apps/worker/pages/locales/en.js";
import { detach, expect, expectSignInPage, signInWithButton, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { RP_HOST, authorizeFlow } from "../support/rp.js";

test("a disabled user is sent to sign in and the passkey is refused", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await finishCodeFlow(page, idp, client, flow);

  await admin.disableUser(user.userId);
  const toRp: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).hostname === RP_HOST) toRp.push(request.url());
  });

  // The session went with the user, so the request is not answered from it.
  const passkeys = await detach(authenticators, user.authenticatorId);
  const next = authorizeFlow(client);
  await page.goto(next.url);
  await signInWithButton(page, authenticators, passkeys);
  await expect(page.getByRole("alert")).toHaveText(`${en.failed} (${en.error_type}: passkey_rejected)`);
  await expectSignInPage(page);
  expect(toRp).toEqual([]);
  const sessions = await idp.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(user.userId).first();
  expect(sessions).toEqual({ n: 0 });
});
