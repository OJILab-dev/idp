// Scenario 2: sign-in from an RP's /authorize, through conditional mediation and through the button, ending in a code
// redirect that the RP exchanges (authentication.md, steps 1 to 8).
import { detach, expect, signInWithButton, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { IDP_HOST } from "../support/idp.js";
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

  const cookies = await page.context().cookies(`https://${IDP_HOST}`);
  expect(cookies.map((c) => c.name)).toEqual(["__Host-session"]);
  expect(cookies[0]).toMatchObject({ domain: IDP_HOST, path: "/", secure: true, httpOnly: true, sameSite: "Lax" });
});

test("the button signs in when no passkey was offered by autofill", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  // With no authenticator while the page loads, the autofill request stays pending, as when the user ignores it.
  const passkeys = await detach(authenticators, user.authenticatorId);

  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await signInWithButton(page, authenticators, passkeys);
  await finishCodeFlow(page, idp, client, flow);
});
