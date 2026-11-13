// Scenario 12: the hosts the hosting mode decides (docs/design/hosting-modes.md 1.3, 2.1, 2.2). The suite runs once per
// mode (support/hosting.ts); in workers_dev the issuer is idp.<subdomain>.workers.dev, where the account's other
// Workers are same-site neighbours, so the session and the passkey must stay on the issuer host exactly. The RP ID is
// checked by the enrollment scenario.
import { expect, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { HOSTING } from "../support/hosting.js";
import { IDP_HOST, ISSUER } from "../support/idp.js";
import { authorizeFlow } from "../support/rp.js";

test("the session cookie is host-only on the issuer, a same-site neighbour gets none, and no related origin is allowed", async ({
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

  // __Host-: Secure, Path=/, and no Domain attribute, so the cookie is host-only (draft-ietf-httpbis-rfc6265bis-22
  // §4.1.3.2); a Domain attribute would show as a leading dot or a parent domain here.
  const cookies = await page.context().cookies(`https://${IDP_HOST}`);
  expect(cookies.map((c) => c.name)).toEqual(["__Host-session"]);
  expect(cookies[0]).toMatchObject({ domain: IDP_HOST, path: "/", secure: true, httpOnly: true, sameSite: "Lax" });
  // A neighbour on the same registrable domain is sent none of them. Asked of the browser itself, by a real request:
  // Playwright's cookies(url) filter matches a host-only cookie by domain suffix, so it would report one here.
  const own = await page.goto(`${ISSUER}/signin`);
  expect(await own?.request().headerValue("cookie")).toMatch(/(^|; )__Host-session=/);
  const neighbour = await page.goto(`https://${HOSTING.neighbourHost}/signin`);
  expect(neighbour?.status()).toBe(404);
  expect(await neighbour?.request().headerValue("cookie")).toBeNull();

  // WebAuthn Level 3 §5.11: a /.well-known/webauthn here would let the origins it lists use this RP ID.
  const related = await idp.dispatch(`${ISSUER}/.well-known/webauthn`);
  expect(related.status).toBe(404);
});
