// The /webauthn/* routes end to end: a software authenticator built on WebCrypto signs for the issuer's RP, and every
// request goes through the Worker's fetch handler against a local D1 with the migrations.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { authenticationResponse, generateCredential, registrationResponse, type SoftCredential } from "../../../packages/core/test/webauthn-authenticator.js";
import { MAX_PASSKEYS_PER_USER, base64urlEncode, sha256Base64url } from "../../../packages/core/src/shared/index.js";
import {
  CLIENT,
  CONFIDENTIAL_SECRET,
  NOW,
  PKCE,
  REDIRECT_URI,
  RP,
  USER,
  VERSION_ID,
  addSoftPasskey,
  authorizeQuery,
  call,
  cookieValue,
  fromEdge,
  locationParams,
  setCookies,
  useFixture,
  type CallOptions,
  type Fixture,
} from "./fixture.js";

const SESSION = "__Host-session";
const AUTHORIZE_REQUEST = "__Host-authorize_request";
const SAME_ORIGIN = { "sec-fetch-site": "same-origin" } as const;
const ENROLL_TOKEN = "ZW5yb2xsLXRva2VuLWVucm9sbC10b2tlbi1lbnJvbGw";

type Options = { readonly challenge: string } & Readonly<Record<string, unknown>>;

function idOf(credential: SoftCredential): string {
  return base64urlEncode(credential.id);
}

function basic(id: string, secret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;
}

/** A same-origin call from one of the pages. */
function page(f: Fixture, method: string, path: string, options: CallOptions = {}): Promise<Response> {
  return call(f, method, path, { ...options, headers: { ...SAME_ORIGIN, ...options.headers } });
}

async function options(res: Response): Promise<Options> {
  expect(res.status).toBe(200);
  return (await res.json()) as Options;
}

async function expectRefusal(res: Response, status: number, error: string): Promise<void> {
  expect(res.status).toBe(status);
  // The body names only the kind of refusal, never which check failed.
  expect(await res.json()).toEqual({ error });
}

/** Seeds an enabled user with one software passkey, an enabled confidential client, and a grant. */
async function seedUser(f: Fixture): Promise<SoftCredential> {
  await f.core.addUser(USER);
  const passkey = await addSoftPasskey(f, USER, NOW - 4000);
  await f.core.addClient({ id: CLIENT, redirectUris: [REDIRECT_URI] });
  await f.core.grant(USER, CLIENT);
  return passkey;
}

async function startAuthorize(f: Fixture): Promise<string> {
  const res = await call(f, "GET", `/authorize?${authorizeQuery({}, PKCE.challenge)}`);
  expect(res.status).toBe(303);
  return cookieValue(setCookies(res).get(AUTHORIZE_REQUEST));
}

async function signIn(f: Fixture, passkey: SoftCredential, requestId: string): Promise<string> {
  const cookies = { [AUTHORIZE_REQUEST]: requestId };
  const { challenge } = await options(await page(f, "POST", "/webauthn/auth/options", { cookies }));
  const credential = await authenticationResponse(passkey, challenge, RP);
  const res = await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential } });
  expect(res.status).toBe(204);
  return cookieValue(setCookies(res).get(SESSION));
}

describe("passkey sign-in", () => {
  const fixture = useFixture();

  it("runs /authorize, the sign-in, /authorize/resume, and /token in order", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const requestId = await startAuthorize(f);

    const cookies = { [AUTHORIZE_REQUEST]: requestId };
    const opts = await options(await page(f, "POST", "/webauthn/auth/options", { cookies }));
    // Discoverable credentials with UV, which also serves conditional mediation.
    expect(opts).toMatchObject({ rpId: RP.rpId, allowCredentials: [], userVerification: "required", timeout: 600_000 });

    const credential = await authenticationResponse(passkey, opts.challenge, RP);
    const verified = await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential } });
    expect(verified.status).toBe(204);
    const sessionLine = setCookies(verified).get(SESSION);
    expect(sessionLine).toMatch(/; Max-Age=3600; /);
    expect(sessionLine).toMatch(/; Path=\//);
    expect(sessionLine).toMatch(/; HttpOnly/);
    expect(sessionLine).toMatch(/; Secure/);
    expect(sessionLine).toMatch(/; SameSite=Lax/);
    expect(sessionLine).not.toMatch(/Domain=/i);
    const session = cookieValue(sessionLine);

    const resumed = await page(f, "POST", "/authorize/resume", { cookies: { ...cookies, [SESSION]: session } });
    expect(resumed.status).toBe(303);
    const code = locationParams(resumed).get("code");
    expect(code).toBeTruthy();

    const token = await call(f, "POST", "/token", {
      headers: { authorization: basic(CLIENT, CONFIDENTIAL_SECRET) },
      form: { grant_type: "authorization_code", code: code ?? "", redirect_uri: REDIRECT_URI, code_verifier: PKCE.verifier },
    });
    expect(token.status).toBe(200);
    expect(await token.json()).toMatchObject({ token_type: "Bearer", id_token: expect.any(String) });
  });

  it("refuses options without the authorize request cookie, writing no challenge", async () => {
    const f = fixture();
    await seedUser(f);
    await expectRefusal(await page(f, "POST", "/webauthn/auth/options"), 403, "passkey_rejected");
    expect(await f.core.query("SELECT 1 FROM challenges")).toHaveLength(0);
  });

  it("refuses a replayed assertion with the same generic body and creates no second session", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const requestId = await startAuthorize(f);
    const cookies = { [AUTHORIZE_REQUEST]: requestId };
    const { challenge } = await options(await page(f, "POST", "/webauthn/auth/options", { cookies }));
    const credential = await authenticationResponse(passkey, challenge, RP);
    expect((await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential } })).status).toBe(204);

    const replay = await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential } });
    await expectRefusal(replay, 403, "passkey_rejected");
    expect(setCookies(replay).has(SESSION)).toBe(false);
    expect(await f.core.query("SELECT 1 FROM sessions")).toHaveLength(1);
  });

  it("refuses an assertion signed for another origin and one by an unknown passkey alike", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const requestId = await startAuthorize(f);
    const cookies = { [AUTHORIZE_REQUEST]: requestId };
    const { challenge } = await options(await page(f, "POST", "/webauthn/auth/options", { cookies }));
    const phished = await authenticationResponse(passkey, challenge, { ...RP, origin: "https://evil.example.net" });
    await expectRefusal(await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential: phished } }), 403, "passkey_rejected");
    const stranger = await authenticationResponse(await generateCredential(-8), challenge, RP);
    await expectRefusal(await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential: stranger } }), 403, "passkey_rejected");
  });

  it("refuses a disabled user's sign-in without saying why", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const requestId = await startAuthorize(f);
    const cookies = { [AUTHORIZE_REQUEST]: requestId };
    const { challenge } = await options(await page(f, "POST", "/webauthn/auth/options", { cookies }));
    await f.core.setUserEnabled(USER, false);
    const credential = await authenticationResponse(passkey, challenge, RP);
    await expectRefusal(await page(f, "POST", "/webauthn/auth/verify", { cookies, json: { credential } }), 403, "passkey_rejected");
  });
});

describe("request checks shared by every /webauthn route", () => {
  const fixture = useFixture();

  const POSTS = [
    "/webauthn/auth/options",
    "/webauthn/auth/verify",
    "/webauthn/register/options",
    "/webauthn/register/verify",
    "/webauthn/add/begin",
    "/webauthn/add/options",
    "/webauthn/add/verify",
    "/webauthn/revoke/begin",
    "/webauthn/revoke/verify",
  ] as const;

  it.each(POSTS)("refuses a cross-site POST %s before touching the database", async (path) => {
    const f = fixture();
    const passkey = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(passkey));
    for (const headers of [{ "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }, { origin: "https://evil.example.net" }, {}]) {
      const res = await call(f, "POST", path, { headers, cookies: { [SESSION]: session }, json: { token: ENROLL_TOKEN, credential_id: "x", credential: {} } });
      await expectRefusal(res, 403, "cross_origin_request");
    }
    expect(await f.core.query("SELECT 1 FROM challenges")).toHaveLength(0);
  });

  it.each([
    ["GET", "/webauthn/auth/options"],
    ["POST", "/webauthn/credentials"],
    ["POST", "/webauthn/unknown"],
  ])("%s %s is 404 from the pages too", async (method, path) => {
    const res = await page(fixture(), method, path);
    expect(res.status).toBe(404);
  });

  it("serves every method and path the page scripts call", async () => {
    const f = fixture();
    const calls = ["signin", "enroll", "account"].flatMap((name) => {
      const source = readFileSync(join(import.meta.dirname, "..", "pages", `${name}.ts`), "utf8");
      return [...source.matchAll(/api\("(GET|POST)", "(\/webauthn\/[a-z/]+)"/g)].map((m) => [m[1] ?? "", m[2] ?? ""] as const);
    });
    expect(calls.length).toBeGreaterThanOrEqual(10);
    for (const [method, path] of calls) expect((await page(f, method, path)).status, `${method} ${path}`).not.toBe(404);
  });

  it("answers an unexpected failure with a 500 that names nothing", async () => {
    const f = fixture();
    const env = { ...f.env, DB: { prepare: () => ({}), batch: () => Promise.reject(new Error("D1 is down")) } as unknown as D1Database };
    const res = await page(f, "POST", "/webauthn/add/begin", { env, cookies: { [SESSION]: base64urlEncode(new Uint8Array(32)) } });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toMatch(/D1/);
  });

  it("accepts a POST with a matching Origin when Sec-Fetch-Site is absent", async () => {
    const f = fixture();
    await seedUser(f);
    const requestId = await startAuthorize(f);
    const res = await call(f, "POST", "/webauthn/auth/options", { headers: { origin: RP.origin }, cookies: { [AUTHORIZE_REQUEST]: requestId } });
    expect(res.status).toBe(200);
  });

  it.each([
    ["no body", undefined, undefined],
    ["a form body", undefined, "application/x-www-form-urlencoded"],
    ["a JSON array", [], undefined],
    ["a JSON string", "token", undefined],
    ["a token that is not a string", { token: 1 }, undefined],
  ])("refuses %s as invalid_request", async (_name, json, contentType) => {
    const f = fixture();
    const res = await page(f, "POST", "/webauthn/register/options", {
      ...(json === undefined ? {} : { json }),
      ...(contentType === undefined ? {} : { headers: { "content-type": contentType } }),
    });
    await expectRefusal(res, 400, "invalid_request");
  });

  it("refuses a body that is not JSON and a body over the size limit", async () => {
    const f = fixture();
    const broken = new Request(`${RP.origin}/webauthn/register/options`, {
      method: "POST",
      headers: { ...SAME_ORIGIN, "content-type": "application/json" },
      body: "{",
    });
    await expectRefusal(await f.handler.fetch(fromEdge(broken), f.env, {} as ExecutionContext), 400, "invalid_request");
    const big = await page(f, "POST", "/webauthn/register/options", { json: { token: ENROLL_TOKEN, pad: "x".repeat(70_000) } });
    await expectRefusal(big, 400, "invalid_request");
  });
});

describe("enrollment through an enroll link", () => {
  const fixture = useFixture();

  async function seedToken(f: Fixture, expiresAt = NOW + 600): Promise<void> {
    await f.core.addUser(USER);
    await f.core.run("INSERT INTO enroll_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)", await sha256Base64url(ENROLL_TOKEN), USER, expiresAt);
  }

  async function newCredential(f: Fixture): Promise<SoftCredential> {
    const [row] = await f.core.query("SELECT user_handle FROM users WHERE id = ?", USER);
    return generateCredential(-8, { userHandle: row?.["user_handle"] as Uint8Array });
  }

  it("registers the passkey, consumes the token, audits it with the Worker's version, and lets the user sign in", async () => {
    const f = fixture();
    await seedToken(f);
    const opts = await options(await page(f, "POST", "/webauthn/register/options", { json: { token: ENROLL_TOKEN } }));
    expect(opts).toMatchObject({ rp: { id: RP.rpId }, attestation: "none", excludeCredentials: [], authenticatorSelection: { residentKey: "required", userVerification: "required" } });

    const passkey = await newCredential(f);
    const credential = await registrationResponse(passkey, opts.challenge, RP);
    const res = await page(f, "POST", "/webauthn/register/verify", { json: { token: ENROLL_TOKEN, credential } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ credential_id: idOf(passkey) });

    expect(await f.core.query("SELECT created_via FROM credentials WHERE id = ?", idOf(passkey))).toEqual([{ created_via: "enroll" }]);
    expect(await f.core.query("SELECT 1 FROM enroll_tokens")).toHaveLength(0);
    expect(await f.core.query("SELECT operation, actor, writer_version FROM audit_log")).toEqual([
      { operation: "passkey_enroll", actor: "user", writer_version: `idp@${VERSION_ID}` },
    ]);

    // A lost response retried: the token is gone, so the page must send the user to sign in instead.
    await expectRefusal(await page(f, "POST", "/webauthn/register/verify", { json: { token: ENROLL_TOKEN, credential } }), 403, "passkey_rejected");

    await f.core.addClient({ id: CLIENT, redirectUris: [REDIRECT_URI] });
    await f.core.grant(USER, CLIENT);
    expect(await signIn(f, passkey, await startAuthorize(f))).toBeTruthy();
  });

  it("refuses an expired token without saying why", async () => {
    const f = fixture();
    await seedToken(f, NOW - 1);
    await expectRefusal(await page(f, "POST", "/webauthn/register/options", { json: { token: ENROLL_TOKEN } }), 403, "passkey_rejected");
  });

  it("tells the user the passkey limit is reached", async () => {
    const f = fixture();
    await seedToken(f);
    for (let i = 0; i < MAX_PASSKEYS_PER_USER; i++) await addSoftPasskey(f, USER, NOW - 4000 + i);
    const res = await page(f, "POST", "/webauthn/register/options", { json: { token: ENROLL_TOKEN } });
    await expectRefusal(res, 409, "limit_reached");
  });
});

describe("the account page's API", () => {
  const fixture = useFixture();

  async function listed(f: Fixture, session: string): Promise<readonly Readonly<Record<string, unknown>>[]> {
    const res = await page(f, "GET", "/webauthn/credentials", { cookies: { [SESSION]: session } });
    expect(res.status).toBe(200);
    return ((await res.json()) as { credentials: Readonly<Record<string, unknown>>[] }).credentials;
  }

  async function add(f: Fixture, session: string, signer: SoftCredential): Promise<SoftCredential> {
    const cookies = { [SESSION]: session };
    const reauth = await options(await page(f, "POST", "/webauthn/add/begin", { cookies }));
    const assertion = await authenticationResponse(signer, reauth.challenge, RP);
    const creation = await options(await page(f, "POST", "/webauthn/add/options", { cookies, json: { credential: assertion } }));
    expect(creation["excludeCredentials"]).toEqual(expect.arrayContaining([{ type: "public-key", id: idOf(signer) }]));
    const [row] = await f.core.query("SELECT user_handle FROM users WHERE id = ?", USER);
    const passkey = await generateCredential(-7, { userHandle: row?.["user_handle"] as Uint8Array });
    const res = await page(f, "POST", "/webauthn/add/verify", { cookies, json: { credential: await registrationResponse(passkey, creation.challenge, RP) } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ credential_id: idOf(passkey) });
    return passkey;
  }

  async function revoke(f: Fixture, session: string, target: SoftCredential, signer: SoftCredential): Promise<Response> {
    const cookies = { [SESSION]: session };
    const reauth = await options(await page(f, "POST", "/webauthn/revoke/begin", { cookies, json: { credential_id: idOf(target) } }));
    const assertion = await authenticationResponse(signer, reauth.challenge, RP);
    return page(f, "POST", "/webauthn/revoke/verify", { cookies, json: { credential_id: idOf(target), credential: assertion } });
  }

  it("lists only the fields the design allows", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(passkey));
    expect(await listed(f, session)).toEqual([
      { credential_id: idOf(passkey), created_at: NOW - 4000, last_used_at: null, created_via: "enroll", backup_state: true },
    ]);
  });

  it("refuses the list without a session, and for a disabled user", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    await expectRefusal(await page(f, "GET", "/webauthn/credentials"), 401, "no_session");
    const session = await f.core.addSession(USER, idOf(passkey));
    await f.core.setUserEnabled(USER, false);
    await expectRefusal(await page(f, "GET", "/webauthn/credentials", { cookies: { [SESSION]: session } }), 403, "passkey_rejected");
  });

  it("refuses the list unless Sec-Fetch-Site is same-origin, even with a matching Origin", async () => {
    const f = fixture();
    const passkey = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(passkey));
    for (const headers of [{ origin: RP.origin }, { "sec-fetch-site": "none" }, { "sec-fetch-site": "cross-site" }, {}]) {
      await expectRefusal(await call(f, "GET", "/webauthn/credentials", { headers, cookies: { [SESSION]: session } }), 403, "cross_origin_request");
    }
  });

  it("adds a passkey after re-authenticating, then revokes it, keeping the session", async () => {
    const f = fixture();
    const first = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(first));
    const second = await add(f, session, first);
    expect((await listed(f, session)).map((p) => [p["credential_id"], p["created_via"]])).toEqual([
      [idOf(first), "enroll"],
      [idOf(second), "self"],
    ]);

    const res = await revoke(f, session, second, first);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ session_ended: false });
    expect(setCookies(res).has(SESSION)).toBe(false);
    expect((await listed(f, session)).map((p) => p["credential_id"])).toEqual([idOf(first)]);
    expect((await f.core.query("SELECT operation, writer_version FROM audit_log ORDER BY id")).map((r) => r["operation"])).toEqual([
      "passkey_add",
      "passkey_self_revoke",
    ]);
  });

  it("refuses to revoke the last passkey", async () => {
    const f = fixture();
    const only = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(only));
    await expectRefusal(await page(f, "POST", "/webauthn/revoke/begin", { cookies: { [SESSION]: session }, json: { credential_id: idOf(only) } }), 409, "last_passkey");
    expect(await f.core.query("SELECT 1 FROM credentials")).toHaveLength(1);
  });

  it("ends the sessions made with a revoked passkey, clears the cookie, and keeps the other passkey's sessions", async () => {
    const f = fixture();
    const first = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(first));
    const second = await add(f, session, first);
    const otherDevice = await f.core.addSession(USER, idOf(second));

    // Re-authenticated with the passkey being revoked: allowed, since another remains.
    const res = await revoke(f, session, first, first);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ session_ended: true });
    expect(setCookies(res).get(SESSION)).toMatch(/Max-Age=0/);

    await expectRefusal(await page(f, "GET", "/webauthn/credentials", { cookies: { [SESSION]: session } }), 401, "no_session");
    expect((await listed(f, otherDevice)).map((p) => p["credential_id"])).toEqual([idOf(second)]);
  });

  it("refuses an add whose re-authentication is by another user's passkey", async () => {
    const f = fixture();
    const mine = await seedUser(f);
    const session = await f.core.addSession(USER, idOf(mine));
    const other = "00000000-0000-4000-8000-000000000002";
    await f.core.addUser(other);
    const theirs = await addSoftPasskey(f, other, NOW - 3000);
    const cookies = { [SESSION]: session };
    const reauth = await options(await page(f, "POST", "/webauthn/add/begin", { cookies }));
    const assertion = await authenticationResponse(theirs, reauth.challenge, RP);
    await expectRefusal(await page(f, "POST", "/webauthn/add/options", { cookies, json: { credential: assertion } }), 403, "passkey_rejected");
  });

  it("refuses add and revoke without a session", async () => {
    const f = fixture();
    await seedUser(f);
    await expectRefusal(await page(f, "POST", "/webauthn/add/begin"), 401, "no_session");
    await expectRefusal(await page(f, "POST", "/webauthn/revoke/begin", { json: { credential_id: "Y3JlZA" } }), 401, "no_session");
  });
});
