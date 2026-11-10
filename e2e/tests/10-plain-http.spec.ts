// Scenario 10: plain http and the admin gate without any zone rule in front (docs/design/domain-placement.md, 3). The
// IdP Worker runs before its static pages, so it alone redirects a page to https and refuses /token over http; the
// admin Worker redirects nothing and refuses what reaches it without a signature.
import { expect, test } from "../support/fixtures.js";
import { ADMIN_HOST, ISSUER } from "../support/idp.js";

test("a page requested over plain http is redirected to the same path on the https issuer, and then served", async ({ idp }) => {
  const plain = await idp.dispatch("http://idp.test/signin?lang=ja");
  expect(plain.status).toBe(308);
  expect(plain.headers.get("location")).toBe(`${ISSUER}/signin?lang=ja`);
  // The redirect is the Worker's, so the static page itself never went out over http.
  expect(await plain.text()).toBe("");

  const secure = await idp.dispatch(`${ISSUER}/signin?lang=ja`);
  expect(secure.status).toBe(200);
  expect(await secure.text()).toMatch(/<html/i);
});

test("a plain http page visit carrying the service's parent-domain cookies is still redirected", async ({ idp }) => {
  const plain = await idp.dispatch("http://idp.test/signin", { headers: { cookie: "theme=dark; _ga=GA1.2.3" } });
  expect(plain.status).toBe(308);
  expect(plain.headers.get("location")).toBe(`${ISSUER}/signin`);
});

test("the page is no-store while its hashed scripts and stylesheet may be cached", async ({ idp }) => {
  const page = await idp.dispatch(`${ISSUER}/signin`);
  expect(page.headers.get("cache-control")).toBe("no-store");
  const html = await page.text();
  const scripts = [...html.matchAll(/(?:src|href)="(\/assets\/[^"]+\.js)"/g)].map((match) => match[1]);
  expect(scripts.length).toBeGreaterThan(0);
  for (const script of scripts) {
    const response = await idp.dispatch(`${ISSUER}${script}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  }
  const style = await idp.dispatch(`${ISSUER}/style.css`);
  expect(style.headers.get("cache-control")).toBe("public, max-age=3600");
  expect(style.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
});

test("/token over plain http is refused without processing and without a redirect", async ({ idp }) => {
  const response = await idp.dispatch("http://idp.test/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${btoa("app:secret")}` },
    body: "grant_type=authorization_code&code=x",
  });
  expect(response.status).toBe(404);
  expect(response.headers.get("location")).toBeNull();
  expect(response.headers.get("www-authenticate")).toBeNull();
});

test("the admin host refuses plain http without a redirect", async ({ idp }) => {
  const response = await idp.dispatchAdmin(`http://${ADMIN_HOST}/v1/users`);
  expect(response.status).toBe(403);
  expect(response.headers.get("location")).toBeNull();
  expect(((await response.json()) as Record<string, unknown>)["type"]).toBe("urn:ojilab:idp:problem:forbidden");
});

test("the admin Worker's own gate refuses an unsigned https request", async ({ idp }) => {
  const response = await idp.dispatchAdmin(`https://${ADMIN_HOST}/v1/users`, { headers: new Headers({ "cf-connecting-ip": "203.0.113.1" }) });
  expect(response.status).toBe(403);
  expect(((await response.json()) as Record<string, unknown>)["type"]).toBe("urn:ojilab:idp:problem:forbidden");
});
