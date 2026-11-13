// JWS compact serialisation (RFC 7515 §7.1) over WebCrypto, as a strict profile: one signature, a protected header
// of exactly alg, kid, and typ, and the algorithms Ed25519 and RS256. RFC 7515 allows more header parameters and
// other algorithms; this profile refuses them, which removes every way a token could choose its key or change how
// it is processed. No JOSE library is needed for that.
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "@idp/base64url";
import type { JwsAlgorithm, JwsSigningKey, JwsVerificationKey } from "./keys.js";

/** The protected header of every JWS this profile signs and accepts. */
export type JwsHeader = {
  readonly alg: JwsAlgorithm;
  readonly kid: string;
  /** The `typ` header parameter (RFC 7515 §4.1.9), compared exactly. */
  readonly typ: string;
};

/** A JWS whose signature verified; the payload claims are still unchecked. */
export type VerifiedJws = {
  readonly header: JwsHeader;
  readonly payload: Readonly<Record<string, unknown>>;
};

/** What a verification accepts. */
export type JwsVerificationOptions = {
  /** The keys a token may be signed with; the header's kid selects one. */
  readonly keys: readonly JwsVerificationKey[];
  /** The allowlist of algorithms; anything else, including `EdDSA` and `none`, is rejected. */
  readonly algorithms: readonly JwsAlgorithm[];
  /** The one `typ` accepted, compared exactly. */
  readonly typ: string;
};

/** Thrown when a JWS is malformed, uses a disallowed algorithm or key, has the wrong `typ`, or does not verify. */
export class InvalidJwsError extends Error {
  override readonly name = "InvalidJwsError";
}

// Tokens of this profile are well under 2 KiB even with RS256; the cap bounds the work spent on hostile input.
const MAX_TOKEN_LENGTH = 8192;

const HEADER_MEMBERS = ["alg", "kid", "typ"].join();

// RFC 8032 §5.1.6: an Ed25519 signature is 64 bytes. RSA signatures are as long as the modulus.
const ED25519_SIGNATURE_BYTES = 64;

const SIGNATURE_ALGORITHMS = {
  Ed25519: { name: "Ed25519" },
  RS256: { name: "RSASSA-PKCS1-v1_5" },
} as const;

const encoder = new TextEncoder();

/**
 * Computes the base64url JWS signature over a signing input with the key's own algorithm.
 *
 * Exported for test vectors such as RFC 8037 Appendix A.4, whose header this profile would never issue; tokens go
 * through {@link signJwt}.
 *
 * @param key The signing key.
 * @param signingInput `BASE64URL(header) || '.' || BASE64URL(payload)` (RFC 7515 §5.1).
 * @returns The unpadded base64url signature.
 */
export async function createJwsSignature(key: JwsSigningKey, signingInput: string): Promise<string> {
  const signature = await crypto.subtle.sign(SIGNATURE_ALGORITHMS[key.alg], key.privateKey, encoder.encode(signingInput));
  return base64urlEncode(new Uint8Array(signature));
}

/**
 * Signs a JWT with the key's algorithm and a header of exactly `alg`, `kid`, and `typ`.
 *
 * @param key The signing key; its `alg` becomes the header's `alg`.
 * @param typ The token type, for example `JWT` (RFC 7519 §5.1) or `at+jwt` (RFC 9068 §2.1).
 * @param payload The claims, serialised with JSON.stringify.
 * @returns The JWS compact serialisation.
 */
export async function signJwt(key: JwsSigningKey, typ: string, payload: object): Promise<string> {
  const header: JwsHeader = { alg: key.alg, kid: key.kid, typ };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  return `${signingInput}.${await createJwsSignature(key, signingInput)}`;
}

/**
 * Verifies a JWS compact serialisation against an allowlist that binds each algorithm to its key type.
 *
 * Every check that does not need the signature runs first, so a disallowed algorithm or key is rejected before
 * any cryptographic operation (RFC 8725 §3.1). The header may contain only `alg`, `kid`, and `typ`: refusing `jwk`,
 * `jku`, `x5u`, `crit`, and `b64` removes every way a token could choose its key or change how it is processed.
 *
 * @param token The untrusted token.
 * @param options The keys, algorithms, and `typ` to accept.
 * @returns The header and the parsed payload.
 * @throws {InvalidJwsError} The token is longer than 8192 characters; does not have three canonical base64url
 *   segments; the header or payload is not a UTF-8 JSON object; the header has members other than `alg`, `kid`,
 *   `typ`; `alg` is not in the allowlist; no key has the `kid`; the key's algorithm differs from `alg`; `typ`
 *   differs; or the signature does not verify.
 */
export async function verifyJws(token: string, options: JwsVerificationOptions): Promise<VerifiedJws> {
  if (token.length > MAX_TOKEN_LENGTH) {
    throw new InvalidJwsError("token is too long");
  }
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new InvalidJwsError("token is not a JWS compact serialisation");
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  const header = decodeObject(headerSegment, "header");
  if (Object.keys(header).sort().join() !== HEADER_MEMBERS) {
    throw new InvalidJwsError("header must have exactly alg, kid, and typ");
  }
  const alg = options.algorithms.find((allowed) => allowed === header["alg"]);
  if (alg === undefined) {
    throw new InvalidJwsError("alg is not allowed");
  }
  const key = options.keys.find((candidate) => candidate.kid === header["kid"]);
  if (key === undefined) {
    throw new InvalidJwsError("kid is not a configured key");
  }
  if (key.alg !== alg) {
    throw new InvalidJwsError("alg does not match the key type");
  }
  if (header["typ"] !== options.typ) {
    throw new InvalidJwsError("typ does not match");
  }
  const signature = decodeSegment(signatureSegment, "signature");
  if (alg === "Ed25519" && signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new InvalidJwsError("Ed25519 signature is not 64 bytes");
  }
  const signingInput = encoder.encode(`${headerSegment}.${payloadSegment}`);
  if (!(await crypto.subtle.verify(SIGNATURE_ALGORITHMS[alg], key.publicKey, signature, signingInput))) {
    throw new InvalidJwsError("signature does not verify");
  }
  const payload = decodeObject(payloadSegment, "payload");
  return { header: { alg, kid: key.kid, typ: options.typ }, payload };
}

function encodeSegment(value: object): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

function decodeSegment(segment: string, part: string): Uint8Array<ArrayBuffer> {
  try {
    return base64urlDecode(segment);
  } catch (error) {
    if (error instanceof InvalidBase64urlError) {
      throw new InvalidJwsError(`${part} is not canonical base64url`);
    }
    throw error;
  }
}

function decodeObject(segment: string, part: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try {
    // ignoreBOM keeps a leading BOM as content, so JSON.parse rejects it instead of the decoder silently dropping it.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(decodeSegment(segment, part));
    parsed = JSON.parse(text);
  } catch (error) {
    if (error instanceof InvalidJwsError) throw error;
    throw new InvalidJwsError(`${part} is not UTF-8 JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new InvalidJwsError(`${part} is not a JSON object`);
  }
  return parsed as Readonly<Record<string, unknown>>;
}
