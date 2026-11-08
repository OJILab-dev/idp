// /webauthn/add/begin|options|verify and /webauthn/revoke/begin|verify against the real schema: the self-service
// items of docs/design/security-checklist.md (re-authentication, session and credential binding, limit, last
// passkey, disabled user, audit row, and the foreign-key cascade of a revocation).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_PASSKEYS_PER_USER, sha256Base64url } from "../src/shared/index.js";
import {
  addBegin,
  addOptions,
  addVerify,
  revokeBegin,
  revokeVerify,
  type CreationOptionsJson,
  type RequestOptionsJson,
} from "../src/user/index.js";
import { NOW } from "./oidc-fixture.js";
import { createPasskeyFixture, idOf, rp, type PasskeyFixture } from "./passkey-fixture.js";
import {
  authenticationResponse,
  generateCredential,
  registrationResponse,
  type CeremonyOverrides,
  type SoftCredential,
} from "./webauthn-authenticator.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_USER = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const WEB = "web-app";

let f: PasskeyFixture;
let first: SoftCredential;
let session: string;

beforeEach(async () => {
  f = await createPasskeyFixture();
  await f.addUser(USER);
  await f.addUser(OTHER_USER, { name: "Bob" });
  first = await f.addPasskey(USER);
  session = await f.addSession(USER, idOf(first));
});

afterEach(async () => {
  await f.dispose();
});

function expectOptions<T>(result: { readonly kind: "options"; readonly options: T } | { readonly kind: "rejected"; readonly reason: string }): T {
  if (result.kind !== "options") throw new Error(`expected options, got ${result.reason}`);
  return result.options;
}

async function newCredential(): Promise<SoftCredential> {
  const [row] = await f.query("SELECT user_handle FROM users WHERE id = ?", USER);
  return generateCredential(-7, { userHandle: row?.["user_handle"] as Uint8Array });
}

function auditRows() {
  return f.query("SELECT actor, operation, target, result, detail_json FROM audit_log ORDER BY id");
}

describe("self-service add", () => {
  async function begin(token = session): Promise<RequestOptionsJson> {
    return expectOptions(await addBegin(f.passkeyDeps, { sessionToken: token }));
  }

  async function reauth(signer: SoftCredential, challenge: string, o: CeremonyOverrides = {}, token = session) {
    return addOptions(f.passkeyDeps, { sessionToken: token, credential: await authenticationResponse(signer, challenge, rp, o) });
  }

  async function register(credential: SoftCredential, challenge: string, token = session) {
    return addVerify(f.passkeyDeps, { sessionToken: token, credential: await registrationResponse(credential, challenge, rp) });
  }

  it("re-authenticates with the user's own passkey, then stores the new one with created_via self and an audit row", async () => {
    const second = await f.addPasskey(USER);
    await f.addPasskey(OTHER_USER);
    const request = await begin();
    expect(request.allowCredentials).toEqual([idOf(first), idOf(second)].map((id) => ({ type: "public-key", id })));
    expect(request.userVerification).toBe("required");
    expect(await f.query("SELECT purpose, user_id, session_token_hash FROM challenges")).toEqual([
      { purpose: "add_reauth", user_id: USER, session_token_hash: await sha256Base64url(session) },
    ]);

    f.clock.advance(3);
    const creation: CreationOptionsJson = expectOptions(await reauth(second, request.challenge));
    expect(creation.excludeCredentials.map((c) => c.id)).toEqual([idOf(first), idOf(second)]);
    expect(creation.authenticatorSelection.userVerification).toBe("required");
    expect(await f.query("SELECT purpose FROM challenges")).toEqual([{ purpose: "add_register" }]);
    expect(await f.query("SELECT last_used_at FROM credentials WHERE id = ?", idOf(second))).toEqual([{ last_used_at: NOW + 3 }]);

    const added = await newCredential();
    expect(await register(added, creation.challenge)).toEqual({ kind: "registered", credentialId: idOf(added) });
    expect(await f.query("SELECT user_id, created_via FROM credentials WHERE id = ?", idOf(added))).toEqual([{ user_id: USER, created_via: "self" }]);
    expect(await f.count("challenges")).toBe(0);
    expect(await auditRows()).toEqual([
      { actor: "user", operation: "passkey_add", target: `user:${USER}`, result: "success", detail_json: JSON.stringify({ credential_id: idOf(added) }) },
    ]);
  });

  it("needs a session", async () => {
    expect(await addBegin(f.passkeyDeps, { sessionToken: undefined })).toEqual({ kind: "rejected", reason: "no_session" });
    f.clock.advance(3600);
    expect(await addBegin(f.passkeyDeps, { sessionToken: session })).toMatchObject({ reason: "no_session" });
  });

  it("rejects re-authentication by another user's passkey", async () => {
    const theirs = await f.addPasskey(OTHER_USER);
    const request = await begin();
    expect(await reauth(theirs, request.challenge)).toEqual({ kind: "rejected", reason: "unknown_credential" });
    expect(await f.count("challenges", "purpose = 'add_register'")).toBe(0);
  });

  it("rejects re-authentication without user verification", async () => {
    const request = await begin();
    expect(await reauth(first, request.challenge, { flags: 0x01 | 0x08 | 0x10 })).toMatchObject({ reason: "verification_failed" });
  });

  it("rejects a challenge issued to another session", async () => {
    const otherSession = await f.addSession(USER, idOf(first));
    const theirs = await begin(otherSession);
    expect(await reauth(first, theirs.challenge)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    const creation = expectOptions(await reauth(first, theirs.challenge, {}, otherSession));
    expect(await register(await newCredential(), creation.challenge)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(1);
  });

  it("cannot skip the re-authentication: the reauth challenge does not register", async () => {
    const request = await begin();
    expect(await register(await newCredential(), request.challenge)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("audit_log")).toBe(0);
  });

  it("issues no registration challenge when the signer's sign count moved after verification", async () => {
    const request = await begin();
    f.beforeBatch(/'add_register'/, () => f.run("UPDATE credentials SET sign_count = sign_count + 1 WHERE id = ?", idOf(first)));
    expect((await reauth(first, request.challenge)).kind).toBe("rejected");
    expect(await f.count("challenges", "purpose = 'add_register'")).toBe(0);
    expect(await f.query("SELECT sign_count FROM credentials WHERE id = ?", idOf(first))).toEqual([{ sign_count: 1 }]);
  });

  it("consumes the re-authentication challenge once", async () => {
    const request = await begin();
    const response = await authenticationResponse(first, request.challenge, rp);
    expectOptions(await addOptions(f.passkeyDeps, { sessionToken: session, credential: response }));
    expect(await addOptions(f.passkeyDeps, { sessionToken: session, credential: response })).toMatchObject({ reason: "invalid_challenge" });
  });

  it("enforces the passkey limit at every step and in the insert itself", async () => {
    for (let i = 1; i < MAX_PASSKEYS_PER_USER - 1; i++) await f.addPasskey(USER);
    const request = await begin();
    const creation = expectOptions(await reauth(first, request.challenge));
    f.beforeBatch(/INSERT INTO credentials/, async () => {
      await f.addPasskey(USER);
    });
    expect(await register(await newCredential(), creation.challenge)).toEqual({ kind: "rejected", reason: "limit_reached" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(MAX_PASSKEYS_PER_USER);
    expect(await f.count("audit_log")).toBe(0);
    expect(await addBegin(f.passkeyDeps, { sessionToken: session })).toMatchObject({ reason: "limit_reached" });
  });

  it("rechecks a disabled user at begin, options, and verify, and in the insert", async () => {
    const request = await begin();
    const creation = expectOptions(await reauth(first, request.challenge));
    f.beforeBatch(/INSERT INTO credentials/, () => f.setUserEnabled(USER, false));
    expect(await register(await newCredential(), creation.challenge)).toEqual({ kind: "rejected", reason: "user_disabled" });
    expect(await f.count("audit_log")).toBe(0);
    expect(await addBegin(f.passkeyDeps, { sessionToken: session })).toMatchObject({ reason: "user_disabled" });
    await f.setUserEnabled(USER, true);
    const again = await begin();
    await f.setUserEnabled(USER, false);
    expect(await reauth(first, again.challenge)).toMatchObject({ reason: "user_disabled" });
  });
});

describe("self-service revoke", () => {
  let second: SoftCredential;

  beforeEach(async () => {
    second = await f.addPasskey(USER);
  });

  async function begin(target: string, token = session): Promise<RequestOptionsJson> {
    return expectOptions(await revokeBegin(f.passkeyDeps, { sessionToken: token, credentialId: target }));
  }

  async function verify(target: string, signer: SoftCredential, challenge: string, o: CeremonyOverrides = {}) {
    return revokeVerify(f.passkeyDeps, { sessionToken: session, credentialId: target, credential: await authenticationResponse(signer, challenge, rp, o) });
  }

  it("re-authenticates, deletes the passkey with its sessions and their unused codes, and writes an audit row", async () => {
    await f.addClient({ id: WEB });
    const secondSession = await f.addSession(USER, idOf(second));
    await f.run(
      `INSERT INTO auth_codes (code_hash, client_id, user_id, session_token_hash, redirect_uri, code_challenge, scope, auth_time, expires_at)
       VALUES ('code', ?, ?, ?, 'https://app.example.com/callback', 'x', 'openid', ?, ?)`,
      WEB,
      USER,
      await sha256Base64url(secondSession),
      NOW,
      NOW + 60,
    );
    const request = await begin(idOf(second));
    expect(request.allowCredentials.map((c) => c.id)).toEqual([idOf(first), idOf(second)]);
    expect(await f.query("SELECT purpose, target_credential_id FROM challenges")).toEqual([{ purpose: "revoke", target_credential_id: idOf(second) }]);

    expect(await verify(idOf(second), first, request.challenge)).toEqual({ kind: "revoked", sessionEnded: false });
    expect(await f.count("credentials", "id = ?", idOf(second))).toBe(0);
    expect(await f.count("sessions", "token_hash = ?", await sha256Base64url(secondSession))).toBe(0);
    expect(await f.count("auth_codes")).toBe(0);
    expect(await f.count("sessions", "token_hash = ?", await sha256Base64url(session))).toBe(1);
    expect(await f.count("challenges")).toBe(0);
    expect(await auditRows()).toEqual([
      { actor: "user", operation: "passkey_self_revoke", target: `user:${USER}`, result: "success", detail_json: JSON.stringify({ credential_id: idOf(second) }) },
    ]);
  });

  it("lets the re-authenticating passkey revoke itself, ending the session it created", async () => {
    const request = await begin(idOf(first));
    expect(await verify(idOf(first), first, request.challenge)).toEqual({ kind: "revoked", sessionEnded: true });
    expect(await f.count("sessions")).toBe(0);
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(1);
  });

  it("refuses the last passkey at begin", async () => {
    const lone = await createLoneUserSession();
    expect(await revokeBegin(f.passkeyDeps, { sessionToken: lone.session, credentialId: lone.credentialId })).toEqual({
      kind: "rejected",
      reason: "last_passkey",
    });
  });

  it("checks the count in the delete itself, so a concurrent revocation cannot leave zero passkeys", async () => {
    // Sign in with the target so that the concurrent revocation of the other passkey leaves this session alive.
    const targetSession = await f.addSession(USER, idOf(second));
    const request = await begin(idOf(second), targetSession);
    f.beforeBatch(/DELETE FROM credentials/, () => f.run("DELETE FROM credentials WHERE id = ?", idOf(first)));
    const response = await authenticationResponse(second, request.challenge, rp);
    expect(await revokeVerify(f.passkeyDeps, { sessionToken: targetSession, credentialId: idOf(second), credential: response })).toEqual({
      kind: "rejected",
      reason: "last_passkey",
    });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(1);
    expect(await f.count("audit_log")).toBe(0);
    // The challenge is consumed even though the revocation was refused.
    expect(await f.count("challenges")).toBe(0);
  });

  it("deletes nothing when the signer's sign count moved after verification", async () => {
    const request = await begin(idOf(second));
    f.beforeBatch(/DELETE FROM credentials/, () => f.run("UPDATE credentials SET sign_count = sign_count + 1 WHERE id = ?", idOf(first)));
    expect((await verify(idOf(second), first, request.challenge)).kind).toBe("rejected");
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(2);
    expect(await f.count("audit_log")).toBe(0);
    expect(await f.query("SELECT sign_count FROM credentials WHERE id = ?", idOf(first))).toEqual([{ sign_count: 1 }]);
  });

  it("deletes nothing when the challenge is consumed concurrently", async () => {
    const request = await begin(idOf(second));
    f.beforeBatch(/DELETE FROM credentials/, () => f.run("DELETE FROM challenges"));
    expect(await verify(idOf(second), first, request.challenge)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(2);
    expect(await f.count("audit_log")).toBe(0);
  });

  it("rejects a challenge moved to another credential ID", async () => {
    const third = await f.addPasskey(USER);
    const request = await begin(idOf(second));
    expect(await verify(idOf(third), first, request.challenge)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(3);
  });

  it("rejects revoking another user's passkey", async () => {
    const theirs = await f.addPasskey(OTHER_USER);
    expect(await revokeBegin(f.passkeyDeps, { sessionToken: session, credentialId: idOf(theirs) })).toEqual({ kind: "rejected", reason: "unknown_credential" });
    expect(await revokeBegin(f.passkeyDeps, { sessionToken: session, credentialId: "not base64url!" })).toMatchObject({ reason: "invalid_request" });
  });

  it("rejects re-authentication by another user's passkey or without user verification", async () => {
    const theirs = await f.addPasskey(OTHER_USER);
    const request = await begin(idOf(second));
    expect(await verify(idOf(second), theirs, request.challenge)).toMatchObject({ reason: "unknown_credential" });
    expect(await verify(idOf(second), first, request.challenge, { flags: 0x01 | 0x08 | 0x10 })).toMatchObject({ reason: "verification_failed" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(2);
  });

  it("cannot skip the re-authentication: an add challenge does not revoke", async () => {
    const add = expectOptions(await addBegin(f.passkeyDeps, { sessionToken: session }));
    expect(await verify(idOf(second), first, add.challenge)).toMatchObject({ reason: "invalid_challenge" });
  });

  it("rechecks a disabled user in the delete itself", async () => {
    const request = await begin(idOf(second));
    f.beforeBatch(/DELETE FROM credentials/, () => f.setUserEnabled(USER, false));
    expect(await verify(idOf(second), first, request.challenge)).toEqual({ kind: "rejected", reason: "user_disabled" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(2);
    expect(await f.count("audit_log")).toBe(0);
  });
});

async function createLoneUserSession(): Promise<{ readonly session: string; readonly credentialId: string }> {
  const lone = await f.addPasskey(OTHER_USER);
  return { session: await f.addSession(OTHER_USER, idOf(lone)), credentialId: idOf(lone) };
}
