// The UserInfo endpoint (OIDC Core §5.3). The access token only says who and which client; whether the user still
// exists, is enabled, and may use that client is re-read from D1 on every call, so a disabled user or a removed
// grant stops working before the 5-minute token expires (security-checklist.md, Pocket ID CVE-2026-43983).
import type { OidcDeps } from "./deps.js";
import { InvalidTokenError } from "./jws.js";
import { verifyAccessToken } from "./tokens.js";

/** A request to `/userinfo` (GET or POST): only the `Authorization` header carries the token (RFC 6750 §2.1). */
export type UserinfoInput = {
  /** The `Authorization` header; `undefined` when absent. */
  readonly authorization: string | undefined;
};

/** The claims returned (OIDC Core §5.3.2): `sub` always, `name` with the profile scope. */
export type UserinfoClaims = { readonly sub: string; readonly name?: string };

/** What the HTTP layer sends. Errors have no body; the `WWW-Authenticate` header carries them (RFC 6750 §3). */
export type UserinfoResponse = {
  readonly status: 200 | 400 | 401;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: UserinfoClaims | null;
};

// RFC 6750 §2.1: the scheme, one space, and a b64token. The scheme name is case-insensitive (RFC 9110 §11.1).
const BEARER = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i;

const NO_STORE: Readonly<Record<string, string>> = { "Cache-Control": "no-store", Pragma: "no-cache" };

/**
 * Handles `/userinfo`.
 *
 * @param deps The database, issuer, keys, and clock.
 * @param input The `Authorization` header.
 * @returns 200 with the claims; 401 without an error code when no token was sent; 400 `invalid_request` for a
 *   malformed header; 401 `invalid_token` for a token that fails verification, has expired, or names a user who is
 *   missing, disabled, or no longer has access to the token's client.
 * @throws {DatabaseError} The read failed.
 */
export async function userinfo(deps: Pick<OidcDeps, "db" | "issuer" | "keys" | "clock">, input: UserinfoInput): Promise<UserinfoResponse> {
  const realm = `Bearer realm="${deps.issuer.url}"`;
  if (input.authorization === undefined) return { status: 401, headers: { ...NO_STORE, "WWW-Authenticate": realm }, body: null };
  const token = BEARER.exec(input.authorization)?.[1];
  if (token === undefined) {
    return { status: 400, headers: { ...NO_STORE, "WWW-Authenticate": `${realm}, error="invalid_request"` }, body: null };
  }
  const invalidToken: UserinfoResponse = {
    status: 401,
    headers: { ...NO_STORE, "WWW-Authenticate": `${realm}, error="invalid_token"` },
    body: null,
  };

  let claims;
  try {
    claims = await verifyAccessToken(token, { issuer: deps.issuer, keys: deps.keys, now: deps.clock.now() });
  } catch (error) {
    if (error instanceof InvalidTokenError) return invalidToken;
    throw error;
  }
  const [result] = await deps.db.batch([
    {
      sql: `SELECT u.name FROM users u
            WHERE u.id = ? AND EXISTS (SELECT 1 FROM effective_access ea WHERE ea.user_id = u.id AND ea.client_id = ?)`,
      params: [claims.sub, claims.client_id],
    },
  ]);
  const name = result?.rows[0]?.["name"];
  if (typeof name !== "string") return invalidToken;
  return {
    status: 200,
    headers: NO_STORE,
    body: { sub: claims.sub, ...(claims.scopes.includes("profile") ? { name } : {}) },
  };
}
