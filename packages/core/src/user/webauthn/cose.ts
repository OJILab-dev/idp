// COSE public keys (RFC 9052 §7, RFC 9053) for exactly the three algorithms the IdP offers in pubKeyCredParams
// (docs/design/standards-compliance.md): -8 (EdDSA over Ed25519), -7 (ES256), and -257 (RS256). Any other key type,
// curve, or algorithm is rejected at registration, so a stored key is always one these functions can verify with.
import { base64urlEncode } from "@idp/base64url";
import { InvalidCborError, decodeCbor, type CborValue } from "@idp/cbor";

/** The COSE algorithms offered and accepted, in the order the IdP prefers them (WebAuthn Level 3 §5.4). */
export const COSE_ALGORITHMS = [-8, -7, -257] as const;

/** One of {@link COSE_ALGORITHMS}. */
export type CoseAlgorithm = (typeof COSE_ALGORITHMS)[number];

/** A credential public key imported for verification. */
export type CosePublicKey = {
  readonly alg: CoseAlgorithm;
  readonly key: CryptoKey;
};

/** Thrown when a COSE key is malformed, uses an algorithm outside {@link COSE_ALGORITHMS}, or does not import. */
export class InvalidCoseKeyError extends Error {
  override readonly name = "InvalidCoseKeyError";
}

// COSE key common parameters (RFC 9052 §7.1) and key type parameters (RFC 9053 §7.1, §7.2; RFC 8230 §4).
const KTY = 1;
const ALG = 3;
const CRV_OR_N = -1;
const X_OR_E = -2;
const Y = -3;

const KTY_OKP = 1;
const KTY_EC2 = 2;
const KTY_RSA = 3;
const CRV_P256 = 1;
const CRV_ED25519 = 6;

// RFC 8230 §6 and RFC 7518 §3.3 both require at least 2048-bit RSA keys. 4096 bits caps the cost of a verification
// that anyone can trigger with a key they registered; authenticators use 2048.
const MIN_RSA_MODULUS_BITS = 2048;
const MAX_RSA_MODULUS_BITS = 4096;

// The only public exponent accepted: what authenticators (TPM included) use. e = 1 would make every signature its
// own message, and small exponents invite padding forgeries, so nothing else is let through.
const RSA_EXPONENT_65537 = [0x01, 0x00, 0x01];

// The bit length of an unsigned big-endian integer without leading zero bytes.
function bitLength(bytes: Uint8Array): number {
  const first = bytes[0] ?? 0;
  return first === 0 ? 0 : (bytes.length - 1) * 8 + (32 - Math.clz32(first));
}

function bytesParam(map: ReadonlyMap<number | string, CborValue>, label: number): Uint8Array {
  const value = map.get(label);
  if (!(value instanceof Uint8Array)) throw new InvalidCoseKeyError(`COSE key parameter ${label} is not a byte string`);
  return value;
}

/**
 * Imports a COSE public key as stored in credentials.public_key.
 *
 * @param bytes The CBOR-encoded COSE_Key.
 * @returns The algorithm and a WebCrypto key usable for `verify`.
 * @throws {InvalidCoseKeyError} The bytes are not a CBOR map; the key type, curve, and algorithm are not one of
 *   OKP/Ed25519/-8, EC2/P-256/-7, or RSA/-257; a coordinate has the wrong length; the RSA modulus is not 2048 to
 *   4096 bits or the exponent is not 65537; or WebCrypto rejects the key (for example a point not on the curve).
 */
export async function importCosePublicKey(bytes: Uint8Array): Promise<CosePublicKey> {
  let map: CborValue;
  try {
    map = decodeCbor(bytes);
  } catch (error) {
    if (error instanceof InvalidCborError) throw new InvalidCoseKeyError(`COSE key is not CBOR: ${error.message}`);
    throw error;
  }
  if (!(map instanceof Map)) throw new InvalidCoseKeyError("COSE key is not a map");
  const kty = map.get(KTY);
  const alg = map.get(ALG);
  try {
    if (kty === KTY_OKP && alg === -8 && map.get(CRV_OR_N) === CRV_ED25519) {
      const x = bytesParam(map, X_OR_E);
      if (x.length !== 32) throw new InvalidCoseKeyError("Ed25519 key is not 32 bytes");
      return { alg, key: await crypto.subtle.importKey("raw", x, { name: "Ed25519" }, false, ["verify"]) };
    }
    if (kty === KTY_EC2 && alg === -7 && map.get(CRV_OR_N) === CRV_P256) {
      const x = bytesParam(map, X_OR_E);
      const y = bytesParam(map, Y);
      if (x.length !== 32 || y.length !== 32) throw new InvalidCoseKeyError("P-256 coordinate is not 32 bytes");
      const point = new Uint8Array(65);
      point[0] = 0x04;
      point.set(x, 1);
      point.set(y, 33);
      return { alg, key: await crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]) };
    }
    if (kty === KTY_RSA && alg === -257) {
      const n = bytesParam(map, CRV_OR_N);
      const e = bytesParam(map, X_OR_E);
      // Counted on the bytes (a leading 0x01 byte is 2041 bits, not 2048), then confirmed on the imported key.
      const bits = bitLength(n);
      if (bits < MIN_RSA_MODULUS_BITS || bits > MAX_RSA_MODULUS_BITS) throw new InvalidCoseKeyError("RSA modulus is not 2048 to 4096 bits");
      if (e.length !== RSA_EXPONENT_65537.length || !e.every((byte, i) => byte === RSA_EXPONENT_65537[i])) {
        throw new InvalidCoseKeyError("RSA public exponent is not 65537");
      }
      const jwk = { kty: "RSA", n: base64urlEncode(n), e: base64urlEncode(e), ext: true };
      const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      const { modulusLength } = key.algorithm as { readonly modulusLength: number };
      if (modulusLength < MIN_RSA_MODULUS_BITS || modulusLength > MAX_RSA_MODULUS_BITS) {
        throw new InvalidCoseKeyError("RSA modulus is not 2048 to 4096 bits");
      }
      return { alg, key };
    }
  } catch (error) {
    if (error instanceof InvalidCoseKeyError) throw error;
    throw new InvalidCoseKeyError("WebCrypto rejected the COSE key");
  }
  throw new InvalidCoseKeyError("COSE key type, curve, or algorithm is not offered");
}

/**
 * Verifies a WebAuthn signature with a credential public key.
 *
 * ES256 signatures arrive DER-encoded (WebAuthn Level 3 §6.5.6), while WebCrypto takes r || s, so they are converted
 * first; a DER encoding that is not minimal fails, so one signature has exactly one accepted spelling.
 *
 * @param key The imported credential public key.
 * @param signature The signature from the authenticator.
 * @param data `authenticatorData || SHA-256(clientDataJSON)`.
 * @returns Whether the signature is valid; malformed signatures are invalid, never an error.
 */
export async function verifyCoseSignature(key: CosePublicKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  switch (key.alg) {
    case -8:
      return signature.length === 64 && crypto.subtle.verify({ name: "Ed25519" }, key.key, signature, data);
    case -7: {
      const raw = derToRawEcdsa(signature);
      return raw !== undefined && crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key.key, raw, data);
    }
    case -257:
      return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key.key, signature, data);
  }
}

// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (RFC 3279 §2.2.3), strict DER, for P-256.
function derToRawEcdsa(der: Uint8Array): Uint8Array | undefined {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) return undefined;
  const out = new Uint8Array(64);
  let offset = 2;
  for (const target of [0, 32]) {
    if (der[offset] !== 0x02) return undefined;
    const length = der[offset + 1] ?? 0;
    const start = offset + 2;
    const integer = der.subarray(start, start + length);
    if (length === 0 || integer.length !== length || length > 33) return undefined;
    const first = integer[0] ?? 0;
    // Positive and minimal: a leading 0x00 only when the next byte has its top bit set.
    if (first & 0x80) return undefined;
    if (first === 0 && (length === 1 || ((integer[1] ?? 0) & 0x80) === 0)) return undefined;
    const value = first === 0 ? integer.subarray(1) : integer;
    if (value.length > 32) return undefined;
    out.set(value, target + 32 - value.length);
    offset = start + length;
  }
  return offset === der.length ? out : undefined;
}
