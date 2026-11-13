// Scenario 13: RP-Initiated Logout 1.0 ends the IdP session, so the next /authorize asks for the passkey again
// (authentication.md, "RP からのログアウト").
import { detach, expect, signInWithButton, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { IDP_HOST, ISSUER } from "../support/idp.js";
import { authorizeFlow, idpRequest, RP_HOST } from "../support/rp.js";
import { POST_LOGOUT_REDIRECT_URI } from "../support/seed.js";

test("a logout with the RP's ID token ends the session at once, returns to the RP with state, and the next sign-in needs the passkey", async ({
  page,
  admin,
  authenticators,
  idp,
}) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  const signedIn = await finishCodeFlow(page, idp, client, flow);

  // The RP finds the endpoint in discovery, as RP-Initiated Logout §2.1 has it.
  const discovery = JSON.parse((await idpRequest(idp, "GET", "/.well-known/openid-configuration")).body) as { end_session_endpoint: string };
  const logout = new URLSearchParams({ id_token_hint: signedIn.idTokenJwt, post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI, state: "bye-1" });
  await page.goto(`${discovery.end_session_endpoint}?${logout.toString()}`);
  await page.waitForURL((url) => url.origin === `https://${RP_HOST}`);
  expect(page.url()).toBe(`${POST_LOGOUT_REDIRECT_URI}?state=bye-1`);
  expect(await page.context().cookies(`https://${IDP_HOST}`)).toEqual([]);
  const sessions = await idp.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(user.userId).first();
  expect(sessions).toEqual({ n: 0 });

  const passkeys = await detach(authenticators, user.authenticatorId);
  const next = authorizeFlow(client);
  await page.goto(next.url);
  await signInWithButton(page, authenticators, passkeys);
  await finishCodeFlow(page, idp, client, next);
});

test("a logout without a hint asks first: staying signed in ends nothing, and confirming ends the session and returns to the RP", async ({
  page,
  admin,
  authenticators,
  idp,
}) => {
  const user = await enrolledUser(admin, page, authenticators);
  const client = await admin.createClient("confidential", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await finishCodeFlow(page, idp, client, flow);
  const logout = new URLSearchParams({ client_id: client.clientId, post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI, state: "bye-2" });

  await page.goto(`${ISSUER}/end_session?${logout.toString()}`);
  await page.getByRole("link", { name: "Stay signed in" }).click();
  await page.waitForURL(`${ISSUER}/account`);
  // The session still answers a plain request with a code, without a sign-in.
  const next = authorizeFlow(client);
  await page.goto(next.url);
  await finishCodeFlow(page, idp, client, next);

  await page.goto(`${ISSUER}/end_session?${logout.toString()}`);
  const before = await idp.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(user.userId).first();
  expect(before).toEqual({ n: 1 });
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL((url) => url.origin === `https://${RP_HOST}`);
  expect(page.url()).toBe(`${POST_LOGOUT_REDIRECT_URI}?state=bye-2`);
  const after = await idp.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(user.userId).first();
  expect(after).toEqual({ n: 0 });
});
