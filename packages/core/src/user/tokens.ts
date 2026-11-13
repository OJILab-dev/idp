// The ID token and access token claims. docs/design/tokens.md (the table and "クレームの一覧") is the only list of
// claims; the builders emit exactly those, so a claim the design rules out (azp, at_hash, acr, amr, sid, email,
// preferred_username, scope in the ID token) cannot appear.
import { InvalidJwsError, signJwt, verifyJws, type JwsAlgorithm, type JwsVerificationOptions, type VerifiedJws } from "@idp/jws";
import { isClientId, isRandomTokenFormat, isUuidV4, randomToken } from "../identifiers/index.js";
import type { Issuer } from "../issuer/index.js";
import type { SigningKey, SigningKeySet } from "./signing-keys.js";

/** The `typ` header: `JWT` for ID tokens, `at+jwt` for access tokens (RFC 9068 §2.1), so neither passes as the other. */
export type JwtType = "JWT" | "at+jwt";

/** Thrown when a token is malformed, uses a disallowed algorithm or key, has the wrong `typ`, or fails a claim check. */
export class InvalidTokenError extends Error {
  override readonly name = "InvalidTokenError";
}

function signToken(key: SigningKey, typ: JwtType, claims: object): Promise<string> {
  return signJwt(key, typ, claims);
}

// The JWS checks of @idp/jws, with its error wrapped so the HTTP layer sees one error type for every token failure.
async function verifyToken(token: string, options: JwsVerificationOptions & { readonly typ: JwtType }): Promise<VerifiedJws> {
  try {
    return await verifyJws(token, options);
  } catch (error) {
    if (error instanceof InvalidJwsError) throw new InvalidTokenError(error.message, { cause: error });
    throw error;
  }
}

/** The lifetime of both ID tokens and access tokens; also the token response's `expires_in`. */
export const TOKEN_LIFETIME_SECONDS = 300;

/** The scopes the IdP grants; every other requested scope (`email` included) is ignored before this point. */
export type GrantedScope = "openid" | "profile";

/** The ID token payload (OIDC Core §2, §5.4). */
export type IdTokenClaims = {
  readonly iss: string;
  readonly sub: string;
  /** The client ID, as a single string. */
  readonly aud: string;
  readonly exp: number;
  readonly iat: number;
  /** Always present, so the token's shape does not depend on whether max_age was requested. */
  readonly auth_time: number;
  /** Present exactly when the authorization request had a nonce. */
  readonly nonce?: string;
  /** Present exactly when the profile scope was granted. */
  readonly name?: string;
};

/** The access token payload (RFC 9068 §2.2). */
export type AccessTokenClaims = {
  readonly iss: string;
  readonly sub: string;
  /** The issuer: the default resource, since `/userinfo` is the only resource (RFC 9068 §3). */
  readonly aud: string;
  readonly client_id: string;
  /** The granted scopes, space-separated (RFC 9068 §2.2.3). */
  readonly scope: string;
  readonly exp: number;
  readonly iat: number;
  readonly jti: string;
};

/** A verified access token: its claims and the parsed `scope`. */
export type VerifiedAccessToken = AccessTokenClaims & { readonly scopes: readonly GrantedScope[] };

/** What an ID token is built from. */
export type IdTokenInput = {
  readonly issuer: Issuer;
  /** The user ID (UUIDv4). */
  readonly sub: string;
  readonly clientId: string;
  /** The session's sign-in time, in UNIX seconds. */
  readonly authTime: number;
  /** The authorization request's nonce; `undefined` when it had none. */
  readonly nonce: string | undefined;
  readonly scopes: readonly GrantedScope[];
  /** The user's display name; emitted only with the profile scope. */
  readonly name: string;
  /** The issue time, in UNIX seconds. */
  readonly now: number;
};

/** What an access token is built from. */
export type AccessTokenInput = {
  readonly issuer: Issuer;
  readonly sub: string;
  readonly clientId: string;
  readonly scopes: readonly GrantedScope[];
  readonly now: number;
};

/** Thrown when a client is registered for RS256 but no RSA key is configured; no token is issued (fail-closed). */
export class SigningAlgorithmUnavailableError extends Error {
  override readonly name = "SigningAlgorithmUnavailableError";
}

/**
 * Builds the ID token claims.
 *
 * @param input The values the token is built from.
 * @returns The claims, with `nonce` and `name` only when they apply.
 */
export function buildIdTokenClaims(input: IdTokenInput): IdTokenClaims {
  return {
    iss: input.issuer.url,
    sub: input.sub,
    aud: input.clientId,
    exp: input.now + TOKEN_LIFETIME_SECONDS,
    iat: input.now,
    auth_time: input.authTime,
    ...(input.nonce === undefined ? {} : { nonce: input.nonce }),
    ...(input.scopes.includes("profile") ? { name: input.name } : {}),
  };
}

/**
 * Builds the access token claims with a fresh random `jti`.
 *
 * @param input The values the token is built from.
 * @returns The claims.
 */
export function buildAccessTokenClaims(input: AccessTokenInput): AccessTokenClaims {
  return {
    iss: input.issuer.url,
    sub: input.sub,
    aud: input.issuer.url,
    client_id: input.clientId,
    scope: input.scopes.join(" "),
    exp: input.now + TOKEN_LIFETIME_SECONDS,
    iat: input.now,
    jti: randomToken(),
  };
}

/**
 * Signs an ID token with the current key of the client's registered algorithm.
 *
 * @param keys The configured keys.
 * @param alg The client's `id_token_signed_response_alg`.
 * @param claims The claims from {@link buildIdTokenClaims}.
 * @returns The signed token (`typ: JWT`).
 * @throws {SigningAlgorithmUnavailableError} `alg` is RS256 and no RSA key is configured. The caller must not fall
 *   back to Ed25519, because the RP expects the algorithm it registered.
 */
export async function signIdToken(keys: SigningKeySet, alg: JwsAlgorithm, claims: IdTokenClaims): Promise<string> {
  const key = alg === "Ed25519" ? keys.ed25519 : keys.rsa;
  if (key === undefined) {
    throw new SigningAlgorithmUnavailableError("RS256 is not enabled: no RSA signing key is configured");
  }
  return signToken(key, "JWT", claims);
}

/**
 * Signs an access token; access tokens are always Ed25519.
 *
 * @param keys The configured keys.
 * @param claims The claims from {@link buildAccessTokenClaims}.
 * @returns The signed token (`typ: at+jwt`).
 */
export async function signAccessToken(keys: SigningKeySet, claims: AccessTokenClaims): Promise<string> {
  return signToken(keys.ed25519, "at+jwt", claims);
}

/**
 * Verifies an access token for `/userinfo`.
 *
 * Only Ed25519 and `typ: at+jwt` are accepted, so an ID token (or an RS256 token of any kind) is never taken as an
 * access token. No clock leeway: the token is the IdP's own and lives only 5 minutes.
 *
 * @param token The bearer token.
 * @param context The issuer, the configured keys, and the current time in UNIX seconds.
 * @returns The claims and the parsed scopes.
 * @throws {InvalidTokenError} The JWS is invalid (see `verifyJws` of `@idp/jws`); `iss` or `aud` is not the issuer string;
 *   `now` is not before `exp`; `sub` is not a UUIDv4; `client_id` is not a client ID; `scope` is not a duplicate-free
 *   set of granted scopes containing `openid`; `exp` or `iat` is not an integer; or `jti` is not a random token.
 */
export async function verifyAccessToken(
  token: string,
  context: { readonly issuer: Issuer; readonly keys: SigningKeySet; readonly now: number },
): Promise<VerifiedAccessToken> {
  const { payload } = await verifyToken(token, {
    keys: context.keys.all,
    algorithms: ["Ed25519"],
    typ: "at+jwt",
  });
  const { iss, sub, aud, client_id, scope, exp, iat, jti } = payload;
  if (iss !== context.issuer.url || aud !== context.issuer.url) {
    throw new InvalidTokenError("iss or aud is not the issuer");
  }
  if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat)) {
    throw new InvalidTokenError("exp or iat is not an integer");
  }
  if (context.now >= (exp as number)) {
    throw new InvalidTokenError("token has expired");
  }
  if (typeof sub !== "string" || !isUuidV4(sub)) {
    throw new InvalidTokenError("sub is not a user ID");
  }
  if (typeof client_id !== "string" || !isClientId(client_id)) {
    throw new InvalidTokenError("client_id is not a client ID");
  }
  if (typeof jti !== "string" || !isRandomTokenFormat(jti)) {
    throw new InvalidTokenError("jti is not a random token");
  }
  const scopes = parseScope(scope);
  return { iss, sub, aud, client_id, scope: scope as string, exp: exp as number, iat: iat as number, jti, scopes };
}

/**
 * Verifies an `id_token_hint`: an ID token this IdP issued, signed by any configured key.
 *
 * `exp` is deliberately not checked: OIDC Core §3.1.2.2 item 5 says the OP SHOULD accept an expired hint when the RP
 * has or had a session, and a hint only narrows who may sign in (docs/design/standards-compliance.md). `aud` is not
 * checked either: the OP must only confirm it is the issuer.
 *
 * @param token The hint from the authorization request.
 * @param context The issuer and the configured keys.
 * @returns The hint's `sub`.
 * @throws {InvalidTokenError} The JWS is invalid (Ed25519 or RS256, `typ: JWT`; see `verifyJws` of `@idp/jws`); `iss` is not
 *   the issuer; or `sub` is not a string.
 */
export async function verifyIdTokenHint(
  token: string,
  context: { readonly issuer: Issuer; readonly keys: SigningKeySet },
): Promise<{ readonly sub: string }> {
  // RS256 is listed unconditionally; a deployment without RSA keys has no RS256 key for a kid to select.
  const { payload } = await verifyToken(token, { keys: context.keys.all, algorithms: ["Ed25519", "RS256"], typ: "JWT" });
  if (payload["iss"] !== context.issuer.url) {
    throw new InvalidTokenError("iss is not the issuer");
  }
  const sub = payload["sub"];
  if (typeof sub !== "string") {
    throw new InvalidTokenError("sub is not a string");
  }
  return { sub };
}

/** The claims of a verified logout `id_token_hint` that RP-Initiated Logout uses. */
export type LogoutIdTokenHint = {
  readonly sub: string;
  /** The client the token was issued to; the IdP always issues a single string. */
  readonly aud: string;
  /** The sign-in time of the session the token came from; `undefined` when the token has none. */
  readonly authTime: number | undefined;
};

/**
 * Verifies the `id_token_hint` of an RP-Initiated Logout request: an ID token this IdP issued (RP-Initiated Logout
 * 1.0 §2, MUST), signed by any configured key, current or previous.
 *
 * `exp` is deliberately not checked: §2 says the OP SHOULD accept an expired ID token when the RP has or had a
 * session, and logging out is what the RP asks for after its own session ended. Unlike {@link verifyIdTokenHint},
 * `aud` must be one client ID, because it names the client whose post-logout redirect URIs apply and must equal a
 * given `client_id` (§2, MUST).
 *
 * @param token The hint from the logout request.
 * @param context The issuer and the configured keys.
 * @returns The hint's `sub`, `aud`, and `auth_time`.
 * @throws {InvalidTokenError} The JWS is invalid (Ed25519 or RS256, `typ: JWT`; see `verifyJws` of `@idp/jws`); `iss` is not
 *   the issuer; `sub` is not a non-empty string; `aud` is not a single client ID; or `auth_time` is present but not
 *   an integer.
 */
export async function verifyLogoutIdTokenHint(
  token: string,
  context: { readonly issuer: Issuer; readonly keys: SigningKeySet },
): Promise<LogoutIdTokenHint> {
  const { payload } = await verifyToken(token, { keys: context.keys.all, algorithms: ["Ed25519", "RS256"], typ: "JWT" });
  if (payload["iss"] !== context.issuer.url) {
    throw new InvalidTokenError("iss is not the issuer");
  }
  const { sub, aud, auth_time: authTime } = payload;
  if (typeof sub !== "string" || sub === "") {
    throw new InvalidTokenError("sub is not a string");
  }
  if (typeof aud !== "string" || !isClientId(aud)) {
    throw new InvalidTokenError("aud is not a single client ID");
  }
  if (authTime !== undefined && !Number.isSafeInteger(authTime)) {
    throw new InvalidTokenError("auth_time is not an integer");
  }
  return { sub, aud, authTime: authTime as number | undefined };
}

function parseScope(scope: unknown): readonly GrantedScope[] {
  if (typeof scope !== "string") {
    throw new InvalidTokenError("scope is not a string");
  }
  const scopes = scope.split(" ");
  const granted = scopes.filter((value): value is GrantedScope => value === "openid" || value === "profile");
  if (granted.length !== scopes.length || new Set(granted).size !== granted.length || !granted.includes("openid")) {
    throw new InvalidTokenError("scope is not a set of granted scopes");
  }
  return granted;
}
