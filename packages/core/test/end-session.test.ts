// RP-Initiated Logout 1.0 (authentication.md, "RP からのログアウト"): one test per branch of endSession's decision.
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  buildIdTokenClaims,
  endSession,
  loadSigningKeys,
  signIdToken,
  type EndSessionInput,
  type EndSessionVia,
  type IdTokenClaims,
  type SigningKeySet,
} from "../src/user/index.js";
import { generateEd25519Jwk } from "./keys.js";
import { createFixture, issuer, NOW, sharedEd25519Keys, type Fixture } from "./oidc-fixture.js";

const RP = "my-app";
const OTHER_RP = "other-app";
const RETURN = "https://app.example.com/signed-out?from=idp";
const SIGNED_IN_AT = NOW - 60;

let f: Fixture;
let keys: SigningKeySet;
let outsider: SigningKeySet;
let session: string;

beforeAll(async () => {
  keys = await sharedEd25519Keys();
  outsider = await loadSigningKeys({ ed25519Current: JSON.stringify(await generateEd25519Jwk()) });
}, 60_000);

beforeEach(async () => {
  f = await createFixture(keys);
  await f.addUser("alice");
  await f.addUser("bob");
  await f.addCredential("cred-a", "alice");
  await f.addCredential("cred-b", "bob");
  await f.addClient({ id: RP, postLogoutRedirectUris: [RETURN] });
  await f.addClient({ id: OTHER_RP, postLogoutRedirectUris: ["https://other.example.com/bye"] });
  session = await f.addSession("alice", "cred-a", SIGNED_IN_AT);
});

afterEach(async () => {
  await f.dispose();
});

function claims(overrides: Partial<Record<keyof IdTokenClaims, unknown>> = {}): IdTokenClaims {
  return {
    ...buildIdTokenClaims({ issuer, sub: "alice", clientId: RP, authTime: SIGNED_IN_AT, nonce: "n", scopes: ["openid"], name: "A", now: NOW - 30 }),
    ...overrides,
  } as IdTokenClaims;
}

function hint(overrides: Partial<Record<keyof IdTokenClaims, unknown>> = {}): Promise<string> {
  return signIdToken(keys, "Ed25519", claims(overrides));
}

function request(
  params: Record<string, string> | readonly (readonly [string, string])[],
  options: { readonly via?: EndSessionVia; readonly cookie?: string | null; readonly acceptLanguage?: string } = {},
): EndSessionInput {
  return {
    params: Array.isArray(params) ? params : Object.entries(params),
    sessionToken: options.cookie === null ? undefined : (options.cookie ?? session),
    acceptLanguage: options.acceptLanguage,
    via: options.via ?? "get",
  };
}

async function sessionCount(): Promise<number> {
  const rows = await f.query("SELECT COUNT(*) AS n FROM sessions");
  return Number(rows[0]?.["n"]);
}

describe("a valid hint from the current session", () => {
  it("ends the session without asking and redirects to the registered URI with state", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), post_logout_redirect_uri: RETURN, state: "s 1" }));
    expect(decision).toEqual({ kind: "redirect", location: `${RETURN}&state=s+1`, sessionEnded: true });
    expect(await sessionCount()).toBe(0);
  });

  it("leaves the user's other sessions alone", async () => {
    await f.addSession("alice", "cred-a", SIGNED_IN_AT - 100);
    await endSession(f.deps, request({ id_token_hint: await hint() }));
    expect(await sessionCount()).toBe(1);
  });

  it("deletes the unused codes issued from the session through the foreign key", async () => {
    const [row] = await f.query("SELECT token_hash FROM sessions");
    await f.run(
      `INSERT INTO auth_codes (code_hash, client_id, user_id, session_token_hash, redirect_uri, code_challenge, scope, auth_time, expires_at)
       VALUES ('code', ?, 'alice', ?, 'https://app.example.com/callback', 'x', 'openid', ?, ?)`,
      RP,
      row?.["token_hash"] ?? null,
      SIGNED_IN_AT,
      NOW + 60,
    );
    await endSession(f.deps, request({ id_token_hint: await hint() }));
    expect(await f.query("SELECT * FROM auth_codes")).toEqual([]);
  });

  it("omits state from the redirect when none is given", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), post_logout_redirect_uri: RETURN }));
    expect(decision).toMatchObject({ kind: "redirect", location: RETURN });
  });

  it("shows the signed-out page when no post_logout_redirect_uri is given", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), state: "s" }));
    expect(decision).toEqual({ kind: "signed_out", locale: "en", sessionEnded: true });
  });

  it("accepts an expired hint (§2 SHOULD)", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint({ iat: NOW - 7200, exp: NOW - 6900 }), post_logout_redirect_uri: RETURN }));
    expect(decision).toMatchObject({ kind: "redirect", sessionEnded: true });
  });

  it("accepts a matching client_id", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), client_id: RP, post_logout_redirect_uri: RETURN }));
    expect(decision).toMatchObject({ kind: "redirect", location: RETURN });
  });

  it("ignores logout_hint and unknown parameters", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), logout_hint: "bob", foo: "bar" }));
    expect(decision).toMatchObject({ kind: "signed_out", sessionEnded: true });
  });

  it("ends the session the same way for a POST with the cookie", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint() }, { via: "post" }));
    expect(decision).toMatchObject({ kind: "signed_out", sessionEnded: true });
  });
});

describe("the confirmation (§2 MUST/SHOULD, §6)", () => {
  it("asks without a hint and ends nothing", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP, post_logout_redirect_uri: RETURN, state: "s" }));
    expect(decision).toEqual({
      kind: "confirm",
      locale: "en",
      otherUser: false,
      form: [
        ["client_id", RP],
        ["post_logout_redirect_uri", RETURN],
        ["state", "s"],
        ["ui_locales", "en"],
      ],
    });
    expect(await sessionCount()).toBe(1);
  });

  it("asks for a hint from an earlier session of the same user (auth_time differs)", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint({ auth_time: SIGNED_IN_AT - 3600 }) }));
    expect(decision).toMatchObject({ kind: "confirm", otherUser: false });
    expect(await sessionCount()).toBe(1);
  });

  it("asks for a hint without auth_time", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint({ auth_time: undefined }) }));
    expect(decision).toMatchObject({ kind: "confirm" });
  });

  it("asks, and says so, when the hint names another user; the other user's session is untouched", async () => {
    await f.addSession("bob", "cred-b", SIGNED_IN_AT);
    const token = await hint({ sub: "bob" });
    const decision = await endSession(f.deps, request({ id_token_hint: token }));
    expect(decision).toMatchObject({ kind: "confirm", otherUser: true, form: [["id_token_hint", token], ["ui_locales", "en"]] });
    expect(await sessionCount()).toBe(2);
    // Confirming ends only the session of the browser that confirmed (alice's), never bob's.
    await endSession(f.deps, request({ id_token_hint: token }, { via: "confirmation" }));
    const rows = await f.query("SELECT user_id FROM sessions");
    expect(rows).toEqual([{ user_id: "bob" }]);
  });

  it("does not carry an unregistered redirect URI or its state into the form", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP, post_logout_redirect_uri: "https://evil.example.com/", state: "s" }));
    expect(decision).toMatchObject({ kind: "confirm", form: [["client_id", RP], ["ui_locales", "en"]] });
  });

  it("asks for a cross-site POST that carries no cookie, because a SameSite=Lax session may still exist", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP }, { via: "post", cookie: null }));
    expect(decision).toMatchObject({ kind: "confirm" });
    expect(await sessionCount()).toBe(1);
  });

  it("asks for a cross-site GET without a hint, so a link cannot sign the user out", async () => {
    const decision = await endSession(f.deps, request({}));
    expect(decision).toMatchObject({ kind: "confirm", form: [["ui_locales", "en"]] });
    expect(await sessionCount()).toBe(1);
  });

  it("ends the session and redirects once confirmed", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP, post_logout_redirect_uri: RETURN, state: "s" }, { via: "confirmation" }));
    expect(decision).toEqual({ kind: "redirect", location: `${RETURN}&state=s`, sessionEnded: true });
    expect(await sessionCount()).toBe(0);
  });

  it("re-validates on confirmation: a forged hint is still refused", async () => {
    const forged = await signIdToken(outsider, "Ed25519", claims());
    const decision = await endSession(f.deps, request({ id_token_hint: forged }, { via: "confirmation" }));
    expect(decision).toMatchObject({ kind: "error_page", error: "invalid_id_token_hint" });
    expect(await sessionCount()).toBe(1);
  });

  it("re-validates on confirmation: an unregistered redirect URI is not followed", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP, post_logout_redirect_uri: "https://evil.example.com/" }, { via: "confirmation" }));
    expect(decision).toEqual({ kind: "signed_out", locale: "en", sessionEnded: true });
  });

  it("uses ui_locales, then Accept-Language", async () => {
    expect(await endSession(f.deps, request({ ui_locales: "fr ja" }))).toMatchObject({ kind: "confirm", locale: "ja", form: [["ui_locales", "ja"]] });
    expect(await endSession(f.deps, request({}, { acceptLanguage: "ja-JP,en;q=0.5" }))).toMatchObject({ locale: "ja" });
  });
});

describe("without a session (§4: not an error)", () => {
  it("treats a GET without the cookie as signed out and still redirects to a registered URI", async () => {
    const decision = await endSession(f.deps, request({ client_id: RP, post_logout_redirect_uri: RETURN, state: "s" }, { cookie: null }));
    expect(decision).toEqual({ kind: "redirect", location: `${RETURN}&state=s`, sessionEnded: false });
  });

  it("treats an expired session cookie as no session", async () => {
    f.clock.advance(3600);
    const decision = await endSession(f.deps, request({}));
    expect(decision).toEqual({ kind: "signed_out", locale: "en", sessionEnded: false });
  });
});

describe("post_logout_redirect_uri (§3: exact match only)", () => {
  it.each([
    ["an unregistered URI", "https://evil.example.com/"],
    ["a different query", "https://app.example.com/signed-out"],
    ["a trailing slash", `${RETURN}/`],
    ["a different case", RETURN.toUpperCase()],
    ["a fragment", `${RETURN}#x`],
    ["another client's URI", "https://other.example.com/bye"],
  ])("does not redirect to %s", async (_, uri) => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), post_logout_redirect_uri: uri, state: "s" }));
    expect(decision).toEqual({ kind: "signed_out", locale: "en", sessionEnded: true });
  });

  it("does not redirect for a disabled client", async () => {
    await f.setClientEnabled(RP, false);
    const decision = await endSession(f.deps, request({ id_token_hint: await hint(), post_logout_redirect_uri: RETURN }));
    expect(decision).toMatchObject({ kind: "signed_out", sessionEnded: true });
  });

  it("does not redirect for a client registered before 0005 (the empty default)", async () => {
    await f.addClient({ id: "legacy" });
    const decision = await endSession(f.deps, request({ client_id: "legacy", post_logout_redirect_uri: RETURN }, { via: "confirmation" }));
    expect(decision).toMatchObject({ kind: "signed_out" });
  });

  it("does not redirect when neither client_id nor a hint names the client", async () => {
    const decision = await endSession(f.deps, request({ post_logout_redirect_uri: RETURN }, { via: "confirmation" }));
    expect(decision).toMatchObject({ kind: "signed_out" });
  });

  it("does not redirect for a hint whose aud names a client that no longer exists", async () => {
    const decision = await endSession(f.deps, request({ id_token_hint: await hint({ aud: "gone-app" }), post_logout_redirect_uri: RETURN }));
    expect(decision).toMatchObject({ kind: "signed_out", sessionEnded: true });
  });
});

describe("refused requests (§4: nothing ended, nothing redirected)", () => {
  async function refused(params: EndSessionInput["params"] | Record<string, string>, error: string, via: EndSessionVia = "get") {
    const decision = await endSession(f.deps, request(params, { via }));
    expect(decision).toEqual({ kind: "error_page", error, locale: "en" });
    expect(await sessionCount()).toBe(1);
  }

  // The hint's claim checks are covered on verifyLogoutIdTokenHint (tokens.test.ts); here only the refusal itself.
  it("refuses a hint signed by a key outside the set", async () => {
    await refused({ id_token_hint: await signIdToken(outsider, "Ed25519", claims()), post_logout_redirect_uri: RETURN }, "invalid_id_token_hint");
  });

  it("refuses a client_id that differs from the hint's aud (§2 MUST)", async () => {
    await refused({ id_token_hint: await hint(), client_id: OTHER_RP, post_logout_redirect_uri: "https://other.example.com/bye" }, "client_id_mismatch");
  });

  it("refuses an unknown client_id", async () => {
    await refused({ client_id: "no-such-app" }, "invalid_client");
  });

  it("refuses a repeated parameter", async () => {
    await refused([["state", "a"], ["state", "b"]], "invalid_request");
  });

  it("refuses a state longer than 2,048 characters", async () => {
    await refused({ state: "s".repeat(2049) }, "invalid_request");
  });

  it("treats an empty value as omitted", async () => {
    const decision = await endSession(f.deps, request([["state", ""], ["state", "x"], ["id_token_hint", ""]]));
    expect(decision).toMatchObject({ kind: "confirm" });
  });
});
