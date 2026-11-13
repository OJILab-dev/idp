// /webauthn/register/options and /webauthn/register/verify against the real schema: the enrollment-link items of
// docs/design/security-checklist.md (token binding, consumption order, limit, disabled user, audit row).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_PASSKEYS_PER_USER, base64urlEncode, sha256Base64url } from "../src/shared/index.js";
import { enrollOptions, enrollVerify, type CreationOptionsJson } from "../src/user/index.js";
import { NOW } from "./oidc-fixture.js";
import { WRITER_VERSION, createPasskeyFixture, idOf, rp, type PasskeyFixture } from "./passkey-fixture.js";
import { generateCredential, registrationResponse, type CeremonyOverrides, type SoftCredential } from "./webauthn-authenticator.js";

const USER = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_USER = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const TOKEN = base64urlEncode(new Uint8Array(32).fill(0x11));
const OTHER_TOKEN = base64urlEncode(new Uint8Array(32).fill(0x22));

let f: PasskeyFixture;

beforeEach(async () => {
  f = await createPasskeyFixture();
  await f.addUser(USER);
  await f.addUser(OTHER_USER, { name: "Bob" });
  await addToken(TOKEN, USER);
});

afterEach(async () => {
  await f.dispose();
});

async function addToken(token: string, userId: string, expiresAt = NOW + 600): Promise<void> {
  await f.run("INSERT INTO enroll_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)", await sha256Base64url(token), userId, expiresAt);
}

async function options(token = TOKEN): Promise<CreationOptionsJson> {
  const result = await enrollOptions(f.passkeyDeps, { enrollToken: token });
  if (result.kind !== "options") throw new Error(`expected options, got ${result.reason}`);
  return result.options;
}

async function newCredential(userId = USER): Promise<SoftCredential> {
  const [row] = await f.query("SELECT user_handle FROM users WHERE id = ?", userId);
  return generateCredential(-8, { userHandle: row?.["user_handle"] as Uint8Array });
}

async function verify(credential: SoftCredential, challenge: string, token = TOKEN, o: CeremonyOverrides = {}) {
  return enrollVerify(f.passkeyDeps, { enrollToken: token, credential: await registrationResponse(credential, challenge, rp, o) });
}

describe("enrollOptions", () => {
  it("issues creation options for a discoverable, user-verified credential bound to the token", async () => {
    const existing = await f.addPasskey(USER);
    const result = await options();
    const [user] = await f.query("SELECT user_handle FROM users WHERE id = ?", USER);
    expect(result).toEqual({
      rp: { id: "idp.example.com", name: "idp.example.com" },
      user: { id: base64urlEncode(user?.["user_handle"] as Uint8Array), name: "Alice", displayName: "Alice" },
      challenge: result.challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 600000,
      excludeCredentials: [{ type: "public-key", id: idOf(existing) }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
    });
    expect(await f.query("SELECT purpose, user_id, enroll_token_hash, expires_at FROM challenges")).toEqual([
      { purpose: "enroll", user_id: USER, enroll_token_hash: await sha256Base64url(TOKEN), expires_at: NOW + 600 },
    ]);
    expect(await f.count("enroll_tokens")).toBe(1);
  });

  it.each(["garbage", OTHER_TOKEN])("rejects the unknown token %s", async (token) => {
    expect(await enrollOptions(f.passkeyDeps, { enrollToken: token })).toEqual({ kind: "rejected", reason: "invalid_enroll_token" });
  });

  it("rejects an expired token", async () => {
    f.clock.advance(600);
    expect(await enrollOptions(f.passkeyDeps, { enrollToken: TOKEN })).toMatchObject({ reason: "invalid_enroll_token" });
  });

  it("rejects a disabled user and a user at the passkey limit", async () => {
    await f.setUserEnabled(USER, false);
    expect(await enrollOptions(f.passkeyDeps, { enrollToken: TOKEN })).toMatchObject({ reason: "user_disabled" });
    await f.setUserEnabled(USER, true);
    for (let i = 0; i < MAX_PASSKEYS_PER_USER; i++) await f.addPasskey(USER);
    expect(await enrollOptions(f.passkeyDeps, { enrollToken: TOKEN })).toMatchObject({ reason: "limit_reached" });
    expect(await f.count("challenges")).toBe(0);
  });
});

describe("enrollVerify", () => {
  it("stores the passkey, consumes the challenge and the token, and writes one audit row in the same batch", async () => {
    const { challenge } = await options();
    const credential = await newCredential();
    expect(await verify(credential, challenge)).toEqual({ kind: "registered", credentialId: idOf(credential) });
    expect(await f.query("SELECT user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via FROM credentials")).toEqual([
      { user_id: USER, public_key: credential.cosePublicKey, sign_count: 0, backup_eligible: 1, backup_state: 1, created_at: NOW, created_via: "enroll" },
    ]);
    expect(await f.count("challenges")).toBe(0);
    expect(await f.count("enroll_tokens")).toBe(0);
    expect(await f.query("SELECT occurred_at, actor, admin_name, writer_version, operation, target, result, detail_json FROM audit_log")).toEqual([
      {
        occurred_at: NOW,
        actor: "user",
        admin_name: null,
        writer_version: WRITER_VERSION,
        operation: "passkey_enroll",
        target: `user:${USER}`,
        result: "success",
        detail_json: JSON.stringify({ credential_id: idOf(credential) }),
      },
    ]);
  });

  it("works only once: the used token is rejected", async () => {
    const { challenge } = await options();
    const credential = await newCredential();
    await verify(credential, challenge);
    expect(await verify(await newCredential(), challenge)).toEqual({ kind: "rejected", reason: "invalid_enroll_token" });
  });

  it("rejects a challenge issued for another enrollment token", async () => {
    await addToken(OTHER_TOKEN, OTHER_USER);
    const { challenge } = await options(OTHER_TOKEN);
    expect(await verify(await newCredential(), challenge, TOKEN)).toEqual({ kind: "rejected", reason: "invalid_challenge" });
    expect(await f.count("credentials")).toBe(0);
  });

  it("rejects an expired token and an expired challenge", async () => {
    const { challenge } = await options();
    f.clock.advance(600);
    expect(await verify(await newCredential(), challenge)).toMatchObject({ reason: "invalid_enroll_token" });
    await addToken(OTHER_TOKEN, USER, NOW + 1800);
    const second = await options(OTHER_TOKEN);
    f.clock.advance(600);
    expect(await verify(await newCredential(), second.challenge, OTHER_TOKEN)).toMatchObject({ reason: "invalid_challenge" });
  });

  it("rejects a registration that fails verification, without consuming the token", async () => {
    const { challenge } = await options();
    expect(await verify(await newCredential(), challenge, TOKEN, { origin: "https://evil.example.com" })).toMatchObject({ reason: "verification_failed" });
    expect(await f.count("enroll_tokens")).toBe(1);
  });

  it("rejects a credential ID already registered to another user, and writes no audit row", async () => {
    const taken = await f.addPasskey(OTHER_USER);
    const { challenge } = await options();
    const clone = await generateCredential(-8, { id: taken.id });
    expect(await verify(clone, challenge)).toEqual({ kind: "rejected", reason: "credential_exists" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(0);
    expect(await f.count("audit_log")).toBe(0);
  });

  it("rejects a user disabled between options and verify, and writes no audit row", async () => {
    const { challenge } = await options();
    await f.setUserEnabled(USER, false);
    expect(await verify(await newCredential(), challenge)).toEqual({ kind: "rejected", reason: "user_disabled" });
    expect(await f.count("credentials")).toBe(0);
    expect(await f.count("audit_log")).toBe(0);
  });

  it("checks the disabled user in the insert itself", async () => {
    const { challenge } = await options();
    f.beforeBatch(/INSERT INTO credentials/, () => f.setUserEnabled(USER, false));
    expect(await verify(await newCredential(), challenge)).toMatchObject({ reason: "user_disabled" });
    expect(await f.count("credentials")).toBe(0);
    expect(await f.count("audit_log")).toBe(0);
  });

  it("checks the passkey limit in the insert itself, so a passkey added meanwhile cannot push past it", async () => {
    for (let i = 0; i < MAX_PASSKEYS_PER_USER - 1; i++) await f.addPasskey(USER);
    const { challenge } = await options();
    f.beforeBatch(/INSERT INTO credentials/, async () => {
      await f.addPasskey(USER, { via: "self" });
    });
    expect(await verify(await newCredential(), challenge)).toEqual({ kind: "rejected", reason: "limit_reached" });
    expect(await f.count("credentials", "user_id = ?", USER)).toBe(MAX_PASSKEYS_PER_USER);
    expect(await f.count("audit_log")).toBe(0);
    // The token is single-use even when the binding was refused.
    expect(await f.count("enroll_tokens")).toBe(0);
  });

  it("stores nothing when the token is deleted between the read and the write", async () => {
    const { challenge } = await options();
    // A re-issued link deletes the user's unused tokens; the challenge goes with it through the foreign key.
    f.beforeBatch(/INSERT INTO credentials/, async () => f.run("DELETE FROM enroll_tokens WHERE token_hash = ?", await sha256Base64url(TOKEN)));
    expect((await verify(await newCredential(), challenge)).kind).toBe("rejected");
    expect(await f.count("credentials")).toBe(0);
    expect(await f.count("audit_log")).toBe(0);
  });

  it("removes the token's challenges with the token, through the foreign key", async () => {
    await options();
    await f.run("DELETE FROM enroll_tokens");
    expect(await f.count("challenges")).toBe(0);
  });
});
