// ID token validation, OIDC Core 1.0 §3.1.3.7, for this IdP: Ed25519 only (RFC 9864 §2.2; the IdP never issues
// the deprecated "EdDSA" nor RS256 to this client, docs/design/tokens.md), the key picked from the JWKS only (by kid,
// or the one usable key when there is no kid) and bound to the algorithm before the signature is checked
// (RFC 8725 §3.1), then iss, aud, exp, iat, and nonce.
import { base64urlDecode, parseJsonObject } from "./encoding.js";

/** Allowed difference between this Worker's clock and the IdP's, in seconds. */
export const CLOCK_SKEW_SECONDS = 60;
/** How old iat may be: the IdP's ID tokens live 5 minutes, and this one was just issued for this login. */
export const MAX_ID_TOKEN_AGE_SECONDS = 600;

/** What the ID token must say. */
export type IdTokenExpectation = {
  readonly issuer: string;
  readonly clientId: string;
  /** The nonce this login sent in the authorization request. */
  readonly nonce: string;
  /** Unix seconds. */
  readonly now: number;
};

/** The checked claims. Only what the IdP issues (tokens.md, クレームの一覧); unknown claims are kept in `claims`. */
export type IdTokenClaims = {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | readonly string[];
  readonly exp: number;
  readonly iat: number;
  readonly nonce: string;
  readonly auth_time?: number;
  readonly name?: string;
  /** Every claim of the payload, for display. */
  readonly claims: Readonly<Record<string, unknown>>;
};

/** Why an ID token was refused; `unknown_kid` tells the caller that a fresh JWKS may help (key rotation). */
export type IdTokenFailure = "format" | "header" | "unknown_kid" | "signature" | "claims" | "iss" | "aud" | "exp" | "iat" | "nonce";

/** The ID token was refused. */
export class IdTokenError extends Error {
  override readonly name = "IdTokenError";
  readonly reason: IdTokenFailure;

  constructor(reason: IdTokenFailure) {
    super(`ID token refused: ${reason}`);
    this.reason = reason;
  }
}

// RFC 7515 §4: header parameters that are not understood MUST be ignored, so unknown members are. Two kinds are
// refused instead: crit, because this RP understands no extension and §4.1.11 requires rejecting a crit it does not
// understand; and the members that carry or point to a key (jwk, jku, x5u, x5c), because the key must come from the
// IdP's JWKS only, never from the token (RFC 8725 §3.1, key injection hardening).
const REFUSED_HEADER_MEMBERS = ["crit", "jwk", "jku", "x5u", "x5c"] as const;

function decodeSegment(segment: string): Record<string, unknown> | undefined {
  const bytes = base64urlDecode(segment);
  return bytes === undefined ? undefined : parseJsonObject(new TextDecoder().decode(bytes));
}

// A usable key: an Ed25519 public signing key; with a kid, that kid.
function isEd25519SigningKey(key: unknown, kid: string | undefined): key is { readonly x: string } {
  if (typeof key !== "object" || key === null) return false;
  const jwk = key as Record<string, unknown>;
  return (
    (kid === undefined || jwk.kid === kid) &&
    jwk.kty === "OKP" &&
    jwk.crv === "Ed25519" &&
    typeof jwk.x === "string" &&
    (jwk.alg === undefined || jwk.alg === "Ed25519") &&
    (jwk.use === undefined || jwk.use === "sig") &&
    jwk.d === undefined
  );
}

function audienceMatches(aud: unknown, azp: unknown, clientId: string): aud is string | readonly string[] {
  // §3.1.3.7 3: aud contains the client_id and no untrusted audience (one audience only: this client trusts no
  // other). §3.1.3.7 5 (errata set 2: MAY): an azp, when present, must be this client.
  if (azp !== undefined && azp !== clientId) return false;
  if (typeof aud === "string") return aud === clientId;
  return Array.isArray(aud) && aud.length === 1 && aud[0] === clientId;
}

/**
 * Validates an ID token from the token endpoint.
 *
 * @param token The compact JWS.
 * @param expected The issuer, client_id, nonce, and time to check against.
 * @param keys The `keys` of the IdP's JWKS, untrusted.
 * @returns The checked claims.
 * @throws {IdTokenError} The token is malformed; its header names another alg or typ, carries crit or a key, or has
 *   a non-string kid; not exactly one Ed25519 signing key matches its kid (or, without a kid, the JWKS); the
 *   signature does not verify; or a claim does not match.
 */
export async function verifyIdToken(token: string, expected: IdTokenExpectation, keys: readonly unknown[]): Promise<IdTokenClaims> {
  const segments = token.split(".");
  if (segments.length !== 3) throw new IdTokenError("format");
  const [headerText = "", payloadText = "", signatureText = ""] = segments;
  const header = decodeSegment(headerText);
  const payload = decodeSegment(payloadText);
  const signature = base64urlDecode(signatureText);
  if (header === undefined || payload === undefined || signature === undefined) throw new IdTokenError("format");

  const { alg, typ, kid } = header;
  if (
    REFUSED_HEADER_MEMBERS.some((member) => member in header) ||
    alg !== "Ed25519" ||
    // RFC 7515 §4.1.9: typ is compared case-insensitively, and "application/" may be omitted (RFC 7519 §5.1: "JWT").
    (typ !== undefined && (typeof typ !== "string" || !["jwt", "application/jwt"].includes(typ.toLowerCase()))) ||
    (kid !== undefined && typeof kid !== "string")
  ) {
    throw new IdTokenError("header");
  }
  // OIDC Core §10.1: kid is required only when the JWKS holds more than one usable key. Without a kid, the token is
  // accepted only against a JWKS with exactly one usable Ed25519 signing key; with one, exactly one key has that kid.
  const candidates = keys.filter((key) => isEd25519SigningKey(key, kid));
  const jwk = candidates.length === 1 ? candidates[0] : undefined;
  if (jwk === undefined) throw new IdTokenError("unknown_kid");

  let valid: boolean;
  try {
    const key = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
    valid = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, new TextEncoder().encode(`${headerText}.${payloadText}`));
  } catch {
    valid = false;
  }
  if (!valid) throw new IdTokenError("signature");

  const { iss, sub, aud, azp, exp, iat, nonce, auth_time: authTime, name } = payload;
  if (typeof sub !== "string" || sub === "" || typeof exp !== "number" || typeof iat !== "number") throw new IdTokenError("claims");
  // §3.1.3.7 2: exactly the issuer, by simple string comparison.
  if (iss !== expected.issuer) throw new IdTokenError("iss");
  if (!audienceMatches(aud, azp, expected.clientId)) throw new IdTokenError("aud");
  // §3.1.3.7 9 and 10.
  if (expected.now >= exp + CLOCK_SKEW_SECONDS) throw new IdTokenError("exp");
  if (iat > expected.now + CLOCK_SKEW_SECONDS || iat < expected.now - MAX_ID_TOKEN_AGE_SECONDS) throw new IdTokenError("iat");
  // §3.1.3.7 11: the nonce this login sent; it binds the token to this browser's login and stops a replay.
  if (typeof nonce !== "string" || nonce !== expected.nonce) throw new IdTokenError("nonce");

  return {
    iss,
    sub,
    aud,
    exp,
    iat,
    nonce,
    ...(typeof authTime === "number" ? { auth_time: authTime } : {}),
    ...(typeof name === "string" ? { name } : {}),
    claims: payload,
  };
}
