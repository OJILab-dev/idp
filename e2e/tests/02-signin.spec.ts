// Scenario 2: sign-in from an RP's /authorize through conditional mediation, ending in a code redirect that the RP
// exchanges (authentication.md, steps 1 to 8). The button path runs in every scenario that signs in again
// (support/fixtures.ts, signInWithButton).
import { expect, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { authorizeFlow } from "../support/rp.js";

test("conditional mediation signs in without a click and the RP gets tokens and userinfo", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  // The page uses conditional mediation only when the browser reports it (WebAuthn Level 3 §5.1.4).
  expect(await page.evaluate("PublicKeyCredential.isConditionalMediationAvailable()")).toBe(true);
  const client = await admin.createClient("confidential", user.userId);

  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  // No click: the autofill request the page starts on load completes with the attached passkey.
  await finishCodeFlow(page, idp, client, flow);
});
