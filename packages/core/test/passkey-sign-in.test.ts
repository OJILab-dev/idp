// /webauthn/auth/options, /webauthn/auth/verify, and GET /webauthn/credentials against the real schema. Each sign-in
// item of docs/design/security-checklist.md (passkeys; sessions) has a case here; the WebAuthn verification steps
// themselves are covered case by case in webauthn-verify.test.ts.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sha256Base64url } from "../src/shared/index.js";
import {
  addBegin,
  authorize,
  listOwnPasskeys,
  resumeAuthorize,
  signInOptions,
  signInVerify,
  type AuthorizeDecision,
  type RequestOptionsJson,
} from "../src/user/index.js";
import { NOW, PKCE } from "./oidc-fixture.js";
import { createPasskeyFixture, idOf, rp, type PasskeyFixture } from "./passkey-fixture.js";
import { authenticationResponse, type CeremonyOverrides, type SoftCredential } from "./webauthn-authenticator.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_USER = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const WEB = "web-app";

let f: PasskeyFixture;
let passkey: SoftCredential;

beforeEach(async () => {
  f = await createPasskeyFixture();
  await f.addUser(USER);
  await f.addUser(OTHER_USER, { name: "Bob" });
  passkey = await f.addPasskey(USER, { alg: -7 });
  await f.addClient({ id: WEB });
  await f.grant(USER, WEB);
});

afterEach(async () => {
  await f.dispose();
});

async function startAuthorize(): Promise<string> {
  const decision: AuthorizeDecision = await authorize(f.deps, {
    params: [
      ["client_id", WEB],
      ["redirect_uri", "https://app.example.com/callback"],
      ["response_type", "code"],
      ["scope", "openid"],
      ["code_challenge", PKCE.challenge],
      ["code_challenge_method", "S256"],
      ["state", "s"],
    ],
    sessionToken: undefined,
    acceptLanguage: undefined,
  });
  if (decision.kind !== "sign_in") throw new Error(`expected sign_in, got ${decision.kind}`);
  return decision.authorizeRequestId;
}

async function options(authorizeRequestId: string | undefined): Promise<RequestOptionsJson> {
  const result = await signInOptions(f.passkeyDeps, { authorizeRequestId });
  if (result.kind !== "options") throw new Error(`expected options, got ${result.reason}`);
  return result.options;
}

async function assertion(credential: SoftCredential, challenge: string, o: CeremonyOverrides = {}): Promise<Record<string, unknown>> {
  return authenticationResponse(credential, challenge, rp, o);
}

describe("signInOptions", () => {
  it("issues a 256-bit, 10-minute challenge bound to the authorize request, for discoverable credentials", async () => {
    const id = await startAuthorize();
    const result = await options(id);
    expect(result).toEqual({ challenge: result.challenge, timeout: 600000, rpId: "idp.example.com", allowCredentials: [], userVerification: "required" });
    expect(Buffer.from(result.challenge, "base64url")).toHaveLength(32);
    expect(await f.query("SELECT purpose, user_id, authorize_request_id_hash, session_token_hash, expires_at FROM challenges")).toEqual([
      { purpose: "sign_in", user_id: null, authorize_request_id_hash: await sha256Base64url(id), session_token_hash: null, expires_at: NOW + 600 },
    ]);
  });

  it("issues a new challenge on every page load", async () => {
    const id = await startAuthorize();
    expect((await options(id)).challenge).not.toBe((await options(id)).challenge);
    expect(await f.count("challenges")).toBe(2);
  });

  it.each([undefined, "garbage", "A".repeat(43)])("rejects the authorize request cookie %s without writing", async (cookie) => {
    expect(await signInOptions(f.passkeyDeps, { authorizeRequestId: cookie })).toEqual({ kind: "rejected", reason: "invalid_authorize_request" });
    expect(await f.count("challenges")).toBe(0);
  });

  it("rejects an expired authorize request", async () => {
    const id = await startAuthorize();
    f.clock.advance(900);
    expect(await signInOptions(f.passkeyDeps, { authorizeRequestId: id })).toMatchObject({ reason: "invalid_authorize_request" });
  });

  it("deletes expired challenges in the same batch", async () => {
    const id = await startAuthorize();
    await options(id);
    f.clock.advance(600);
    await options(id);
    expect(await f.count("challenges")).toBe(1);
  });
});

describe("signInVerify", () => {
  async function verify(authorizeRequestId: string | undefined, credential: unknown, sessionToken?: string) {
    return signInVerify(f.passkeyDeps, { authorizeRequestId, sessionToken, credential });
  }

  it("creates a session bound to the passkey, and /authorize/resume then issues a code", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    f.clock.advance(5);
    const result = await verify(id, await assertion(passkey, challenge));
    if (result.kind !== "signed_in") throw new Error(result.reason);
    expect(result.expiresAt).toBe(NOW + 5 + 3600);
    expect(await f.query("SELECT user_id, credential_id, auth_time, expires_at FROM sessions WHERE token_hash = ?", await sha256Base64url(result.sessionToken))).toEqual([
      { user_id: USER, credential_id: idOf(passkey), auth_time: NOW + 5, expires_at: NOW + 5 + 3600 },
    ]);
    expect(await f.query("SELECT last_used_at FROM credentials WHERE id = ?", idOf(passkey))).toEqual([{ last_used_at: NOW + 5 }]);
    expect(await f.count("challenges")).toBe(0);

    const decision = await resumeAuthorize(f.deps, { authorizeRequestId: id, sessionToken: result.sessionToken, acceptLanguage: undefined });
    expect(decision.kind).toBe("code_redirect");
  });

  it("consumes the challenge exactly once: a replayed assertion is rejected", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    const response = await assertion(passkey, challenge);
    expect((await verify(id, response)).kind).toBe("signed_in");
    expect(await verify(id, response)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("sessions")).toBe(1);
  });

  it("rejects a challenge issued to another browser's authorize request", async () => {
    const mine = await startAuthorize();
    const theirs = await startAuthorize();
    const { challenge } = await options(theirs);
    expect(await verify(mine, await assertion(passkey, challenge))).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("rejects an expired challenge", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    f.clock.advance(600);
    expect(await verify(id, await assertion(passkey, challenge))).toMatchObject({ reason: "invalid_challenge" });
  });

  it("rejects a real, live challenge issued for another purpose", async () => {
    const id = await startAuthorize();
    const session = await f.addSession(USER, idOf(passkey));
    const reauth = await addBegin(f.passkeyDeps, { sessionToken: session });
    if (reauth.kind !== "options") throw new Error(reauth.reason);
    expect(await f.count("challenges", "challenge = ? AND purpose = 'add_reauth'", reauth.options.challenge)).toBe(1);
    expect(await verify(id, await assertion(passkey, reauth.options.challenge))).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("sessions")).toBe(1);
  });

  it("rejects an assertion whose user handle is another user's", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    const [other] = await f.query("SELECT user_handle FROM users WHERE id = ?", OTHER_USER);
    const response = await assertion(passkey, challenge, { userHandle: other?.["user_handle"] as Uint8Array });
    expect(await verify(id, response)).toEqual({ kind: "rejected", reason: "verification_failed" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("verifies against the IdP's origin and requires the user handle", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    expect(await verify(id, await assertion(passkey, challenge, { origin: "https://evil.example.com" }))).toMatchObject({ reason: "verification_failed" });
    expect(await verify(id, await assertion(passkey, challenge, { userHandle: null }))).toMatchObject({ reason: "verification_failed" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("rejects an unknown credential and a malformed body", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    expect(await verify(id, await assertion(passkey, challenge, { id: "AAAA", rawId: "AAAA" }))).toMatchObject({ reason: "unknown_credential" });
    expect(await verify(id, { type: "public-key" })).toMatchObject({ reason: "invalid_request" });
    expect(await verify(undefined, await assertion(passkey, challenge))).toMatchObject({ reason: "invalid_authorize_request" });
  });

  it("rejects an assertion whose sign count did not increase", async () => {
    const counted = await f.addPasskey(USER, { signCount: 10 });
    const id = await startAuthorize();
    const { challenge } = await options(id);
    expect(await verify(id, await assertion(counted, challenge, { signCount: 10 }))).toMatchObject({ reason: "verification_failed" });
    const result = await verify(id, await assertion(counted, challenge));
    expect(result.kind).toBe("signed_in");
    expect(await f.query("SELECT sign_count FROM credentials WHERE id = ?", idOf(counted))).toEqual([{ sign_count: 12 }]);
  });

  it("updates the sign count by compare-and-set, so a concurrent assertion that moved it first wins alone", async () => {
    const counted = await f.addPasskey(USER, { signCount: 10 });
    const id = await startAuthorize();
    const { challenge } = await options(id);
    // Another ceremony with the same credential stores 11 between this one's read (10) and its write.
    f.beforeBatch(/INSERT INTO sessions/, () => f.run("UPDATE credentials SET sign_count = 11 WHERE id = ?", idOf(counted)));
    expect((await verify(id, await assertion(counted, challenge))).kind).toBe("rejected");
    expect(await f.count("sessions")).toBe(0);
    expect(await f.query("SELECT sign_count FROM credentials WHERE id = ?", idOf(counted))).toEqual([{ sign_count: 11 }]);
  });

  it("creates no session for a disabled user", async () => {
    await f.setUserEnabled(USER, false);
    const id = await startAuthorize();
    const { challenge } = await options(id);
    expect(await verify(id, await assertion(passkey, challenge))).toEqual({ kind: "rejected", reason: "user_disabled" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("creates no session when the user is disabled between the check and the insert", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    f.beforeBatch(/INSERT INTO sessions/, () => f.setUserEnabled(USER, false));
    expect(await verify(id, await assertion(passkey, challenge))).toEqual({ kind: "rejected", reason: "user_disabled" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("creates no session when the challenge is consumed concurrently", async () => {
    const id = await startAuthorize();
    const { challenge } = await options(id);
    f.beforeBatch(/INSERT INTO sessions/, () => f.run("DELETE FROM challenges"));
    expect(await verify(id, await assertion(passkey, challenge))).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("sessions")).toBe(0);
  });

  it("replaces the browser's previous session and deletes expired sessions", async () => {
    const other = await f.addPasskey(OTHER_USER);
    const previous = await f.addSession(USER, idOf(passkey));
    const expired = await f.addSession(OTHER_USER, idOf(other), NOW - 4000);
    const id = await startAuthorize();
    const { challenge } = await options(id);
    const result = await verify(id, await assertion(passkey, challenge), previous);
    expect(result.kind).toBe("signed_in");
    expect(await f.count("sessions", "token_hash IN (?, ?)", await sha256Base64url(previous), await sha256Base64url(expired))).toBe(0);
    expect(await f.count("sessions")).toBe(1);
  });
});

describe("listOwnPasskeys", () => {
  it("returns only the session user's passkeys, with exactly the listed fields", async () => {
    const second = await f.addPasskey(USER, { via: "self" });
    await f.addPasskey(OTHER_USER);
    const session = await f.addSession(USER, idOf(passkey));
    const result = await listOwnPasskeys(f.passkeyDeps, { sessionToken: session });
    if (result.kind !== "passkeys") throw new Error(result.reason);
    expect(result.passkeys.map((p) => p.credential_id)).toEqual([idOf(passkey), idOf(second)]);
    for (const p of result.passkeys) expect(Object.keys(p).sort()).toEqual(["backup_state", "created_at", "created_via", "credential_id", "last_used_at"]);
    expect(result.passkeys[1]).toMatchObject({ created_via: "self", backup_state: true, last_used_at: null });
  });

  it("rejects an absent or expired session and a disabled user", async () => {
    const session = await f.addSession(USER, idOf(passkey));
    expect(await listOwnPasskeys(f.passkeyDeps, { sessionToken: undefined })).toMatchObject({ reason: "no_session" });
    await f.setUserEnabled(USER, false);
    expect(await listOwnPasskeys(f.passkeyDeps, { sessionToken: session })).toMatchObject({ reason: "user_disabled" });
    f.clock.advance(3600);
    expect(await listOwnPasskeys(f.passkeyDeps, { sessionToken: session })).toMatchObject({ reason: "no_session" });
  });
});
