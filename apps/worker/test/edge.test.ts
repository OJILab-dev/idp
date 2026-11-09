// The checks every request passes after the host and scheme check and before any route: the TLS version and the
// per-IP rate limit (docs/design/domain-placement.md, 3 and 4; docs/design/security-checklist.md, "セッションと通信").
import { describe, expect, it } from "vitest";
import { CLIENT_IP, call, useFixture } from "./fixture.js";

describe("the TLS version check (fail-closed)", () => {
  const fixture = useFixture();

  // The zone's minimum TLS version belongs to the zone's owner when the zone is shared, so the Worker refuses TLS
  // below 1.2 itself, as it refuses plain http: with a 404 and without running any route.
  it.each([
    ["TLS 1.0", { tlsVersion: "TLSv1" }],
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
    ["an unknown version", { tlsVersion: "TLSv1.4" }],
    ["no tlsVersion", {}],
    ["no request.cf", null],
  ])("refuses %s with 404 before counting or routing", async (_name, cf) => {
    const f = fixture();
    const res = await call(f, "GET", "/.well-known/openid-configuration", { cf });
    expect(res.status).toBe(404);
    expect(f.rateLimiter.keys).toEqual([]);
  });

  it("refuses TLS 1.1 on /token before the client is authenticated", async () => {
    const f = fixture();
    const res = await call(f, "POST", "/token", { cf: { tlsVersion: "TLSv1.1" }, form: { grant_type: "authorization_code" } });
    expect(res.status).toBe(404);
  });

  it.each(["TLSv1.2", "TLSv1.3"])("serves %s", async (tlsVersion) => {
    const res = await call(fixture(), "GET", "/.well-known/openid-configuration", { cf: { tlsVersion } });
    expect(res.status).toBe(200);
  });
});

describe("the per-IP rate limit (fail-closed)", () => {
  const fixture = useFixture();

  it("counts every request to a route by the client IP, and only by it", async () => {
    const f = fixture();
    await call(f, "GET", "/jwks");
    await call(f, "GET", "/authorize");
    await call(f, "GET", "/.well-known/openid-configuration");
    await call(f, "POST", "/token", { form: {} });
    await call(f, "GET", "/userinfo");
    await call(f, "POST", "/logout");
    await call(f, "POST", "/authorize/resume");
    await call(f, "POST", "/webauthn/auth/options", { json: {} });
    expect(f.rateLimiter.keys).toEqual(Array.from({ length: 8 }, () => CLIENT_IP));
  });

  it("does not count a static page, which writes nothing", async () => {
    const f = fixture();
    await call(f, "GET", "/signin");
    expect(f.rateLimiter.keys).toEqual([]);
  });

  it("refuses a request over the limit with 429 and Retry-After, before any route runs", async () => {
    const f = fixture();
    f.rateLimiter.outcome = "deny";
    const res = await call(f, "POST", "/webauthn/auth/options", { headers: { "sec-fetch-site": "same-origin" }, json: {} });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("10");
    // No challenge row was written: the limit guards the pre-authentication D1 writes.
    expect(await f.core.query("SELECT 1 FROM challenges")).toEqual([]);
  });

  it("refuses with 503 when the binding fails, rather than letting the request through uncounted", async () => {
    const f = fixture();
    f.rateLimiter.outcome = "throw";
    const res = await call(f, "GET", "/jwks");
    expect(res.status).toBe(503);
  });

  it.each([
    ["no CF-Connecting-IP", null],
    ["an empty CF-Connecting-IP", ""],
  ])("refuses a request with %s, since it cannot be counted", async (_name, clientIp) => {
    const f = fixture();
    const res = await call(f, "GET", "/jwks", { clientIp });
    expect(res.status).toBe(400);
    expect(f.rateLimiter.keys).toEqual([]);
  });

  it("is not reached by a request for another host", async () => {
    const f = fixture();
    const res = await call(f, "GET", "/jwks", { origin: "https://evil.example.net" });
    expect(res.status).toBe(404);
    expect(f.rateLimiter.keys).toEqual([]);
  });
});
