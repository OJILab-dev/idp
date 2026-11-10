// Scenario 12: the hosts the hosting mode decides (docs/design/hosting-modes.md 1.3, 2.1, 2.2). The suite runs once per
// mode (support/hosting.ts); in workers_dev the issuer is idp.<subdomain>.workers.dev, where the account's other
// Workers are same-site neighbours, so the passkey and the cookies must stay on the issuer host exactly.
import { expect, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { HOSTING, WORKERS_DEV_SUBDOMAIN } from "../support/hosting.js";
import { ADMIN_HOST, IDP_HOST, ISSUER } from "../support/idp.js";
import { authorizeFlow, idpRequest } from "../support/rp.js";

// Written out, not derived the way support/hosting.ts derives them, so a wrong derivation fails here.
const EXPECTED =
  HOSTING.mode === "workers_dev"
    ? { issuer: `https://idp.${WORKERS_DEV_SUBDOMAIN}.workers.dev`, adminHost: `idp-admin.${WORKERS_DEV_SUBDOMAIN}.workers.dev` }
    : { issuer: "https://idp.test", adminHost: "admin.idp.test" };

test("the issuer is the one the mode derives, and discovery names it and only its host", async ({ idp }) => {
  expect(ISSUER).toBe(EXPECTED.issuer);
  const response = await idpRequest(idp, "GET", "/.well-known/openid-configuration");
  expect(response.status, response.body).toBe(200);
  const document = JSON.parse(response.body) as Readonly<Record<string, unknown>>;
  expect(document["issuer"]).toBe(ISSUER);
  // Every endpoint is on the issuer host: no workers.dev parent and no other Worker's host.
  const endpoints = Object.entries(document).filter(([name]) => name.endsWith("_endpoint") || name === "jwks_uri");
  expect(endpoints.length).toBeGreaterThan(0);
  for (const [name, value] of endpoints) expect(new URL(String(value)).origin, name).toBe(ISSUER);
});

test("the passkey's RP ID is the issuer host exactly, and the session cookie is __Host- on that host", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const [credential] = await authenticators.credentials(user.authenticatorId);
  // Not the registrable domain (<subdomain>.workers.dev in workers_dev), which every Worker of the account shares.
  expect(credential?.rpId).toBe(IDP_HOST);

  const client = await admin.createClient("public", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await finishCodeFlow(page, idp, client, flow);

  const cookies = await page.context().cookies(`https://${IDP_HOST}`);
  expect(cookies.length).toBeGreaterThan(0);
  for (const cookie of cookies) {
    // __Host-: Secure, Path=/, and no Domain attribute, so the cookie is host-only (draft-ietf-httpbis-rfc6265bis-22
    // §4.1.3.2); a Domain attribute would show as a leading dot or a parent domain here.
    expect(cookie.name).toMatch(/^__Host-/);
    expect(cookie).toMatchObject({ domain: IDP_HOST, path: "/", secure: true });
  }
  // A neighbour on the same registrable domain is sent none of them. Asked of the browser itself, by a real request:
  // Playwright's cookies(url) filter matches a host-only cookie by domain suffix, so it would report one here.
  const own = await page.goto(`${ISSUER}/signin`);
  expect(await own?.request().headerValue("cookie")).toMatch(/(^|; )__Host-session=/);
  const neighbour = await page.goto(`https://${HOSTING.neighbourHost}/signin`);
  expect(neighbour?.status()).toBe(404);
  expect(await neighbour?.request().headerValue("cookie")).toBeNull();
});

test("the IdP Worker answers only on the issuer host, and serves no related-origins document", async ({ idp }) => {
  const neighbour = await idp.dispatch(`https://${HOSTING.neighbourHost}/.well-known/openid-configuration`);
  expect(neighbour.status).toBe(404);
  // WebAuthn Level 3 §5.11: a /.well-known/webauthn here would let the origins it lists use this RP ID.
  const related = await idp.dispatch(`${ISSUER}/.well-known/webauthn`);
  expect(related.status).toBe(404);
});

test("the admin Worker answers only on the admin host the mode derives", async ({ idp }) => {
  expect(ADMIN_HOST).toBe(EXPECTED.adminHost);
  const headers = new Headers({ "cf-connecting-ip": "203.0.113.12" });
  const neighbour = await idp.dispatchAdmin(`https://${HOSTING.neighbourHost}/v1/users`, { headers });
  expect(neighbour.status).toBe(403);
  // The issuer host is not an admin host either, in any mode.
  const issuer = await idp.dispatchAdmin(`${ISSUER}/v1/users`, { headers });
  expect(issuer.status).toBe(403);
});
