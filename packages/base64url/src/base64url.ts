// base64url without padding (RFC 4648 §5, RFC 7515 §2), the encoding of every token, secret, hash, and kid in the contract.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Maps a char code to its 6-bit value, or -1 for anything outside the URL-safe alphabet.
const DECODE_TABLE: readonly number[] = Array.from({ length: 128 }, (_, code) =>
  ALPHABET.indexOf(String.fromCharCode(code)),
);

/** Thrown when a string is not canonical, unpadded base64url. */
export class InvalidBase64urlError extends Error {
  override readonly name = "InvalidBase64urlError";
}

/**
 * Encodes bytes as base64url without padding (RFC 4648 §5).
 *
 * @param bytes The bytes to encode.
 * @returns The encoded string; empty for empty input.
 */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const remaining = bytes.length - i;
    out += ALPHABET.charAt(b0 >> 2);
    out += ALPHABET.charAt(((b0 & 0x03) << 4) | (b1 >> 4));
    if (remaining > 1) out += ALPHABET.charAt(((b1 & 0x0f) << 2) | (b2 >> 6));
    if (remaining > 2) out += ALPHABET.charAt(b2 & 0x3f);
  }
  return out;
}

/**
 * Decodes unpadded base64url strictly.
 *
 * Every byte string has exactly one accepted encoding, so a value compared after decoding cannot be smuggled
 * past a check in a second spelling (RFC 4648 §3.5 lets decoders reject non-zero pad bits; we always do).
 *
 * @param encoded The string to decode.
 * @returns The decoded bytes.
 * @throws {InvalidBase64urlError} The string has padding, a character outside the URL-safe alphabet (including
 *   '+', '/', and whitespace), a length that is 1 modulo 4, or non-zero trailing bits.
 */
export function base64urlDecode(encoded: string): Uint8Array {
  if (encoded.length % 4 === 1) {
    throw new InvalidBase64urlError("base64url length is 1 modulo 4");
  }
  const out = new Uint8Array(Math.floor((encoded.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < encoded.length; i++) {
    const value = DECODE_TABLE[encoded.charCodeAt(i)] ?? -1;
    if (value < 0) {
      throw new InvalidBase64urlError("character outside the base64url alphabet");
    }
    buffer = ((buffer << 6) | value) & 0xfff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new InvalidBase64urlError("non-zero trailing bits");
  }
  return out;
}
