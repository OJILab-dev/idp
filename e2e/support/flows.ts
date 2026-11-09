// The steps several scenarios share: a user who has enrolled a passkey, and the RP's side of a finished code flow.
import type { Page } from "@playwright/test";
import type { Authenticators } from "./authenticator.js";
import { enroll, expect } from "./fixtures.js";
import { ISSUER, type LocalIdp } from "./idp.js";
import { exchangeCode, fetchUserinfo, waitForCallback, type Flow } from "./rp.js";
import type { Admin, SeededClient, SeededUser } from "./seed.js";

/** A user with one passkey, held by an authenticator attached to the tab. */
export type EnrolledUser = SeededUser & { readonly authenticatorId: string };

/**
 * Creates a user through the admin use cases and enrolls a passkey through the link in the tab.
 *
 * @returns The user and the authenticator holding the passkey.
 * @throws {Error} A seed step or the enrollment fails.
 */
export async function enrolledUser(admin: Admin, page: Page, authenticators: Authenticators): Promise<EnrolledUser> {
  const user = await admin.createUser("Alice");
  const authenticatorId = await authenticators.add();
  await enroll(page, user.enrollLink);
  return { ...user, authenticatorId };
}

/** The checked result of a code flow, as the RP holds it. */
export type SignedIn = {
  readonly sub: string;
  readonly idToken: Readonly<Record<string, unknown>>;
};

function decodeJwtPayload(jwt: string): Readonly<Record<string, unknown>> {
  const payload = jwt.split(".")[1];
  if (payload === undefined) throw new Error("not a JWS");
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
}

/**
 * Waits for the redirect to the RP and does what the RP does next: checks `iss` and `state` (RFC 9207 §2.4), exchanges
 * the code at /token, and calls /userinfo with the access token.
 *
 * @returns The subject and the ID token's claims.
 * @throws {Error} Any step fails its check.
 */
export async function finishCodeFlow(page: Page, idp: LocalIdp, client: SeededClient, flow: Flow): Promise<SignedIn> {
  const callback = await waitForCallback(page);
  expect(callback.error).toBeNull();
  expect(callback.iss).toBe(ISSUER);
  expect(callback.state).toBe(flow.state);
  expect(callback.code).toBeTruthy();

  const token = await exchangeCode(idp, client, flow, callback.code ?? "");
  expect(token.status, token.body).toBe(200);
  const tokens = JSON.parse(token.body) as { readonly access_token: string; readonly id_token: string; readonly token_type: string };
  expect(tokens.token_type).toBe("Bearer");
  const idToken = decodeJwtPayload(tokens.id_token);
  expect(idToken).toMatchObject({ iss: ISSUER, aud: client.clientId, nonce: flow.nonce });

  const info = await fetchUserinfo(idp, tokens.access_token);
  expect(info.status, info.body).toBe(200);
  const claims = JSON.parse(info.body) as { readonly sub: string };
  expect(claims.sub).toBe(idToken["sub"]);
  return { sub: claims.sub, idToken };
}
