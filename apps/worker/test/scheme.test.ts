// The Worker runs before every request, the static pages included, so it alone decides what plain http gets and
// which TLS versions reach a page (docs/design/domain-placement.md, 3; no zone ruleset is relied on).
import { describe, expect, it } from "vitest";
import { ASSET_PAGE, ISSUER, call, useFixture } from "./fixture.js";

const PLAIN = "http://idp.example.com";

describe("plain http on the issuer host", () => {
  const fixture = useFixture();

  it.each([
    ["GET", "/signin?lang=ja"],
    ["GET", "/authorize?client_id=app&state=a%20b"],
    ["HEAD", "/signin"],
  ])("redirects %s %s with 308 to the same path and query on the configured issuer", async (method, path) => {
    const f = fixture();
    const res = await call(f, method, path, { origin: PLAIN, cf: {} });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe(`${ISSUER}${path}`);
    // Nothing else runs for it: no count, no asset, no route.
    expect(f.rateLimiter.keys).toEqual([]);
    expect(f.assets.requests).toEqual([]);
  });

  it("redirects to the configured issuer even when the request names a port", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/signin", { origin: "http://idp.example.com:8080", cf: {} });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe(`${ISSUER}/signin`);
  });

  it("keeps a path that looks like another authority on the issuer host", async () => {
    const f = fixture();
    const res = await call(f, "GET", "//evil.example.net/x", { origin: PLAIN, cf: {} });
    expect(res.status).toBe(308);
    expect(new URL(res.headers.get("location") ?? "").host).toBe("idp.example.com");
  });

  it("never redirects another host, so the Location is never taken from the request", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/signin", { origin: "http://evil.example.net", cf: {} });
    expect(res.status).toBe(404);
    expect(res.headers.get("location")).toBeNull();
  });

  it.each([
    ["POST", "/token", { form: { grant_type: "authorization_code", code: "x" } }],
    ["PUT", "/signin", {}],
    ["OPTIONS", "/token", {}],
  ])("refuses the unsafe %s %s with 404, without a redirect that would invite a replay", async (method, path, body) => {
    const f = fixture();
    const res = await call(f, method, path, { origin: PLAIN, cf: {}, ...body });
    expect(res.status).toBe(404);
    expect(res.headers.get("location")).toBeNull();
    expect(f.rateLimiter.keys).toEqual([]);
    expect(f.assets.requests).toEqual([]);
  });

  // In a shared zone the service's non-Secure parent-domain cookies ride along with every http request; they are not
  // the IdP's credentials and must not turn the redirect into a 404.
  it.each([
    ["one", "theme=dark"],
    ["several", "theme=dark; _ga=GA1.2.3; lang=ja"],
    ["one whose value mentions __Host-", "note=__Host-session"],
  ])("still redirects a GET carrying %s of the service's cookies", async (_name, cookie) => {
    const f = fixture();
    const res = await call(f, "GET", "/signin", { origin: PLAIN, cf: {}, headers: { cookie } });
    expect(res.status).toBe(308);
    expect(res.headers.get("location")).toBe(`${ISSUER}/signin`);
  });

  it.each([
    ["an Authorization header", { authorization: "Bearer at" }],
    ["a __Host- cookie among the service's cookies", { cookie: "theme=dark;  __Host-authorize_request=r" }],
    ["any __Host- cookie name, whatever its value", { cookie: "__Host-other=" }],
  ])("refuses a GET carrying %s with 404: the credential is already exposed", async (_name, headers) => {
    const f = fixture();
    const res = await call(f, "GET", "/userinfo", { origin: PLAIN, cf: {}, headers });
    expect(res.status).toBe(404);
    expect(res.headers.get("location")).toBeNull();
  });

  it("refuses a scheme other than http and https", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/signin", { origin: "ftp://idp.example.com", cf: {} });
    expect(res.status).toBe(404);
  });
});

describe("the static pages behind the Worker", () => {
  const fixture = useFixture();

  it("serves a page from the assets binding over https with the security headers, without counting it", async () => {
    const f = fixture();
    const res = await call(f, "GET", ASSET_PAGE);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("sign in");
    expect(f.assets.requests).toEqual([`GET ${ASSET_PAGE}`]);
    // Assets are not D1 writes; counting them would refuse an ordinary page load (free-tier.md).
    expect(f.rateLimiter.keys).toEqual([]);
  });

  // The Worker runs before every asset, so a sub-resource re-fetched on every page view would spend the account-wide
  // daily request limit; only public, content-addressed or allowlisted files may be cached.
  it.each([
    ["a hashed script", "/assets/signin-CekN57dd.js", "public, max-age=31536000, immutable"],
    ["the shared hashed script", "/assets/common-DLkd5xV9.js", "public, max-age=31536000, immutable"],
    ["the unhashed stylesheet", "/style.css", "public, max-age=3600"],
  ])("lets %s be cached, with the other security headers kept", async (_name, path, cacheControl) => {
    const f = fixture();
    const res = await call(f, "GET", path, { cacheControl });
    expect(res.status).toBe(200);
  });

  it.each([
    ["an HTML page", ASSET_PAGE, 200],
    ["a script without a content hash", "/assets/plain.js", 200],
    ["HTML under a hashed script name", "/assets/page-AAAAAAAA.js", 200],
    ["a missing hashed script", "/assets/gone-ZZZZZZZZ.js", 404],
  ])("keeps %s no-store", async (_name, path, status) => {
    const res = await call(fixture(), "GET", path);
    expect(res.status).toBe(status);
  });

  it("keeps a cacheable path no-store over plain http, where the answer is a redirect", async () => {
    const res = await call(fixture(), "GET", "/style.css", { origin: PLAIN, cf: {} });
    expect(res.status).toBe(308);
  });

  it.each([
    ["discovery", "GET", "/.well-known/openid-configuration"],
    ["the JWKS", "GET", "/jwks"],
    ["userinfo", "GET", "/userinfo"],
  ])("keeps %s no-store", async (_name, method, path) => {
    await call(fixture(), method, path);
  });

  it("answers a path that is neither a route nor an asset with the asset server's 404", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/no-such-page");
    expect(res.status).toBe(404);
    expect(f.assets.requests).toEqual(["GET /no-such-page"]);
  });

  it("does not hand a POST to the assets binding", async () => {
    const f = fixture();
    const res = await call(f, "POST", ASSET_PAGE, { json: {} });
    expect(res.status).toBe(404);
    expect(f.assets.requests).toEqual([]);
  });

  it.each([
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
  ])("refuses a page over %s like any route", async (_name, cf) => {
    const f = fixture();
    const res = await call(f, "GET", ASSET_PAGE, { cf });
    expect(res.status).toBe(404);
    expect(f.assets.requests).toEqual([]);
  });
});
