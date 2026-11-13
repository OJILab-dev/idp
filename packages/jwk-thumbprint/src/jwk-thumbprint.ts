// The RFC 7638 JWK thumbprint with SHA-256, for the key shapes of RFC 8037 §2 (Ed25519) and RFC 7518 §6.3.1 (RSA).
// The supported shapes are a deliberate subset: other key types and curves are rejected, not hashed.
import { InvalidBase64urlError, base64urlDecode } from "@idp/base64url";
import { sha256Base64url } from "./sha256.js";

// RFC 8032 §5.1.5: an Ed25519 public key is 32 bytes.
const ED25519_PUBLIC_KEY_BYTES = 32;

/** Thrown when a JWK is not one of the key shapes this package supports. */
export class InvalidJwkError extends Error {
  override readonly name = "InvalidJwkError";
}

/**
 * Computes the RFC 7638 JWK thumbprint (SHA-256, unpadded base64url).
 *
 * Only the required members enter the hash, in lexicographic order and without whitespace (RFC 7638 §3.2,
 * §3.3): `crv`, `kty`, `x` for Ed25519 (RFC 8037 §2) and `e`, `kty`, `n` for RSA. Other members such as `alg`,
 * `use`, `kid`, and the private `d` are ignored, so a private JWK and its public half share one kid.
 *
 * @param jwk The parsed JWK, untrusted.
 * @returns The 43-character thumbprint.
 * @throws {InvalidJwkError} The value is not an object; `kty` is neither `OKP` nor `RSA`; an OKP key's `crv` is not
 *   `Ed25519`; a required member is missing, not a string, or not canonical base64url; an Ed25519 `x` is not
 *   32 bytes; or `alg` is the deprecated `EdDSA` (RFC 9864 §4.1.2), rejected fail-closed.
 */
export async function jwkThumbprint(jwk: unknown): Promise<string> {
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
    throw new InvalidJwkError("JWK is not an object");
  }
  const members = jwk as Readonly<Record<string, unknown>>;
  if (members["alg"] === "EdDSA") {
    throw new InvalidJwkError("alg EdDSA is rejected; Ed25519 keys use alg Ed25519");
  }
  // Keys are inserted in lexicographic order; JSON.stringify keeps insertion order for string keys.
  switch (members["kty"]) {
    case "OKP": {
      if (members["crv"] !== "Ed25519") {
        throw new InvalidJwkError("unsupported OKP curve");
      }
      const x = requireBase64urlMember(members, "x");
      if (x.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw new InvalidJwkError("Ed25519 x is not 32 bytes");
      }
      return sha256Base64url(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: members["x"] }));
    }
    case "RSA": {
      requireBase64urlMember(members, "e");
      requireBase64urlMember(members, "n");
      return sha256Base64url(JSON.stringify({ e: members["e"], kty: "RSA", n: members["n"] }));
    }
    default:
      throw new InvalidJwkError("unsupported kty");
  }
}

function requireBase64urlMember(members: Readonly<Record<string, unknown>>, name: string): Uint8Array {
  const value = members[name];
  if (typeof value !== "string") {
    throw new InvalidJwkError(`JWK member ${name} is missing or not a string`);
  }
  try {
    return base64urlDecode(value);
  } catch (error) {
    if (error instanceof InvalidBase64urlError) {
      throw new InvalidJwkError(`JWK member ${name} is not canonical base64url`, { cause: error });
    }
    throw error;
  }
}
