// Scenario 10: plain http without any zone rule in front (docs/design/domain-placement.md, 3). The IdP Worker runs
// before its static pages in the shipped configuration, so it alone redirects a page to https. The unit tests
// (apps/worker/test/scheme.test.ts, apps/admin-worker/test/gate.test.ts) cover /token, the admin host, and the other
// variants with a stand-in asset server; this checks the real one sits behind the Worker.
import { expect, test } from "../support/fixtures.js";
import { IDP_HOST, ISSUER } from "../support/idp.js";

test("a page requested over plain http is redirected to the same path on the https issuer, and then served", async ({ idp }) => {
  const plain = await idp.dispatch(`http://${IDP_HOST}/signin?lang=ja`);
  expect(plain.status).toBe(308);
  expect(plain.headers.get("location")).toBe(`${ISSUER}/signin?lang=ja`);
  // The redirect is the Worker's, so the static page itself never went out over http.
  expect(await plain.text()).toBe("");

  const secure = await idp.dispatch(`${ISSUER}/signin?lang=ja`);
  expect(secure.status).toBe(200);
  expect(await secure.text()).toMatch(/<html/i);
});
