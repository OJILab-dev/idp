// The token endpoint (docs/design/authentication.md, sign-in step 7). The client is identified and its enablement
// checked before it is authenticated, and every check on the code runs before the code is consumed, so a failed
// request never burns a code (security-checklist.md, Pocket ID CVE-2026-28513).
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { isCodeVerifier, s256CodeChallenge } from "@idp/pkce";
import { isClientId, isRandomTokenFormat } from "@idp/core/identifiers";
import type { SqlRow } from "@idp/core/db";
import { CorruptRowError, loadClient, type RegisteredClient } from "./clients.js";
import type { OidcDeps } from "./deps.js";
import {
  TOKEN_LIFETIME_SECONDS,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  signAccessToken,
  signIdToken,
  type GrantedScope,
} from "./tokens.js";

/** A request to `/token`: the `Authorization` header and the form body. */
export type TokenInput = {
  /** The `Authorization` header; `undefined` when absent. */
  readonly authorization: string | undefined;
  /** The `application/x-www-form-urlencoded` body in the order received. */
  readonly params: readonly (readonly [string, string])[];
};

/** The `error` values of the token endpoint (RFC 6749 §5.2), plus `server_error` for the RS256 fail-closed case. */
export type TokenErrorCode = "invalid_request" | "invalid_client" | "invalid_grant" | "unsupported_grant_type" | "server_error";

/** The successful token response (RFC 6749 §5.1, OIDC Core §3.1.3.3). */
export type TokenSuccessBody = {
  readonly access_token: string;
  readonly token_type: "Bearer";
  readonly expires_in: number;
  readonly id_token: string;
  /** Always present: it differs from the request whenever a scope such as `email` was ignored (RFC 6749 §5.1). */
  readonly scope: string;
};

/** What the HTTP layer sends: the status, the headers, and the JSON body. */
export type TokenResponse = {
  readonly status: 200 | 400 | 401 | 500;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: TokenSuccessBody | { readonly error: TokenErrorCode };
};

// RFC 6749 §5.1 and §5.2: token responses carry secrets and must not be cached.
const NO_STORE: Readonly<Record<string, string>> = { "Cache-Control": "no-store", Pragma: "no-cache" };

/**
 * Handles `POST /token` for the authorization code grant.
 *
 * @param deps The database, issuer, keys, clock, and random source.
 * @param input The `Authorization` header and the form parameters.
 * @returns The token response, or an error response that left the code unconsumed (except that a reused or
 *   expired code stays rejected).
 * @throws {CorruptRowError} The client or code row is malformed.
 * @throws {DatabaseError} A read or write failed.
 */
export async function exchangeToken(deps: OidcDeps, input: TokenInput): Promise<TokenResponse> {
  const params = new Map<string, string[]>();
  for (const [name, value] of input.params) {
    if (value === "") continue;
    params.set(name, [...(params.get(name) ?? []), value]);
  }
  // RFC 6749 §3.2: parameters must not repeat.
  if ([...params.values()].some((values) => values.length > 1)) return failure("invalid_request", deps);
  function param(name: string): string | undefined {
    return params.get(name)?.[0];
  }

  const credentials = parseClientCredentials(input.authorization, param("client_id"));
  if (credentials === undefined || !isClientId(credentials.clientId)) return failure("invalid_client", deps);
  const client = await loadClient(deps.db, credentials.clientId);
  // Before authentication (RFC 6749 §5.2): this only reveals that the identifier is unusable, and identifiers are
  // not secret (§2.2).
  if (client === undefined || !client.enabled) return failure("invalid_client", deps);
  if (!(await authenticates(client, credentials.secret, param("client_secret")))) return failure("invalid_client", deps);

  const grantType = param("grant_type");
  if (grantType === undefined) return failure("invalid_request", deps);
  if (grantType !== "authorization_code") return failure("unsupported_grant_type", deps);
  const code = param("code");
  const redirectUri = param("redirect_uri");
  const codeVerifier = param("code_verifier");
  if (code === undefined || redirectUri === undefined || codeVerifier === undefined || !isCodeVerifier(codeVerifier)) {
    return failure("invalid_request", deps);
  }
  if (!isRandomTokenFormat(code)) return failure("invalid_grant", deps);

  const now = deps.clock.now();
  const codeHash = await sha256Base64url(code);
  const [read] = await deps.db.batch([
    {
      sql: `SELECT a.client_id, a.redirect_uri, a.code_challenge, a.expires_at, u.name
            FROM auth_codes a JOIN users u ON u.id = a.user_id WHERE a.code_hash = ?`,
      params: [codeHash],
    },
  ]);
  const row = read?.rows[0];
  if (row === undefined) return failure("invalid_grant", deps);
  const stored = parseCodeRow(row);
  if (
    stored.expiresAt <= now ||
    stored.clientId !== client.id ||
    stored.redirectUri !== redirectUri ||
    (await s256CodeChallenge(codeVerifier)) !== stored.codeChallenge
  ) {
    return failure("invalid_grant", deps);
  }
  // tokens.md: no RS256 key means no token, and the code is kept so nothing is lost once the key is configured.
  if (client.idTokenAlg === "RS256" && deps.keys.rsa === undefined) return failure("server_error", deps);

  // The consuming DELETE repeats the expiry, the issuing session, and effective_access, so the code is taken only
  // if they all still hold at the moment of the write, and two concurrent exchanges cannot both win.
  const [consumed] = await deps.db.batch([
    {
      sql: `DELETE FROM auth_codes
            WHERE code_hash = ? AND client_id = ? AND expires_at > ?
              AND EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash = auth_codes.session_token_hash AND s.expires_at > ?)
              AND EXISTS (SELECT 1 FROM effective_access ea WHERE ea.user_id = auth_codes.user_id AND ea.client_id = auth_codes.client_id)
            RETURNING user_id, nonce, scope, auth_time`,
      params: [codeHash, client.id, now, now],
    },
  ]);
  const taken = consumed?.rows[0];
  if (taken === undefined) return failure("invalid_grant", deps);
  const grant = parseConsumedRow(taken);

  const idToken = await signIdToken(
    deps.keys,
    client.idTokenAlg,
    buildIdTokenClaims({
      issuer: deps.issuer,
      sub: grant.userId,
      clientId: client.id,
      authTime: grant.authTime,
      nonce: grant.nonce,
      scopes: grant.scopes,
      name: stored.name,
      now,
    }),
  );
  const accessToken = await signAccessToken(
    deps.keys,
    buildAccessTokenClaims({ issuer: deps.issuer, sub: grant.userId, clientId: client.id, scopes: grant.scopes, now }),
  );
  return {
    status: 200,
    headers: NO_STORE,
    body: {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_LIFETIME_SECONDS,
      id_token: idToken,
      scope: grant.scopes.join(" "),
    },
  };
}

type ClientCredentials = { readonly clientId: string; readonly secret: string | undefined };

// RFC 6749 §2.3.1: client_secret_basic encodes both halves with application/x-www-form-urlencoded before Base64.
// A request with an Authorization header must identify the same client in both places, if it repeats client_id.
function parseClientCredentials(authorization: string | undefined, bodyClientId: string | undefined): ClientCredentials | undefined {
  if (authorization === undefined) return bodyClientId === undefined ? undefined : { clientId: bodyClientId, secret: undefined };
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(authorization);
  if (match?.[1] === undefined) return undefined;
  let decoded: string;
  try {
    decoded = atob(match[1]);
  } catch {
    return undefined;
  }
  const separator = decoded.indexOf(":");
  if (separator < 0) return undefined;
  const clientId = formDecode(decoded.slice(0, separator));
  const secret = formDecode(decoded.slice(separator + 1));
  if (clientId === undefined || secret === undefined) return undefined;
  if (bodyClientId !== undefined && bodyClientId !== clientId) return undefined;
  return { clientId, secret };
}

function formDecode(value: string): string | undefined {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch {
    return undefined;
  }
}

// Confidential clients authenticate with client_secret_basic only. Public clients send no secret at all: one they
// send is rejected rather than ignored, so a client registered as public cannot be mistaken for an authenticated one
// (RFC 8252 §8.5).
async function authenticates(
  client: RegisteredClient,
  basicSecret: string | undefined,
  bodySecret: string | undefined,
): Promise<boolean> {
  if (bodySecret !== undefined) return false;
  if (client.clientType === "public") return basicSecret === undefined;
  if (basicSecret === undefined || client.secretHash === null) return false;
  return constantTimeEqual(await sha256Base64url(basicSecret), client.secretHash);
}

// Compares two digests without an early exit, so the time taken does not reveal the length of the matching prefix.
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

function failure(error: TokenErrorCode, deps: Pick<OidcDeps, "issuer">): TokenResponse {
  if (error === "invalid_client") {
    // RFC 6749 §5.2: 401 with a challenge for the scheme the server supports.
    return { status: 401, headers: { ...NO_STORE, "WWW-Authenticate": `Basic realm="${deps.issuer.url}"` }, body: { error } };
  }
  return { status: error === "server_error" ? 500 : 400, headers: NO_STORE, body: { error } };
}

type StoredCode = {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly expiresAt: number;
  readonly name: string;
};

function parseCodeRow(row: SqlRow): StoredCode {
  const { client_id, redirect_uri, code_challenge, expires_at, name } = row;
  if (
    typeof client_id !== "string" ||
    typeof redirect_uri !== "string" ||
    typeof code_challenge !== "string" ||
    typeof expires_at !== "number" ||
    typeof name !== "string"
  ) {
    throw new CorruptRowError("auth_codes row is malformed");
  }
  return { clientId: client_id, redirectUri: redirect_uri, codeChallenge: code_challenge, expiresAt: expires_at, name };
}

type ConsumedCode = {
  readonly userId: string;
  readonly nonce: string | undefined;
  readonly scopes: readonly GrantedScope[];
  readonly authTime: number;
};

function parseConsumedRow(row: SqlRow): ConsumedCode {
  const { user_id, nonce, scope, auth_time } = row;
  if (typeof user_id !== "string" || typeof auth_time !== "number" || (nonce !== null && typeof nonce !== "string")) {
    throw new CorruptRowError("auth_codes row is malformed");
  }
  // /authorize writes exactly these two spellings; anything else did not come from it.
  let scopes: readonly GrantedScope[];
  if (scope === "openid") scopes = ["openid"];
  else if (scope === "openid profile") scopes = ["openid", "profile"];
  else throw new CorruptRowError("auth_codes.scope is malformed");
  return { userId: user_id, nonce: nonce ?? undefined, scopes, authTime: auth_time };
}
