import { base64urlEncode } from "@idp/base64url";

/**
 * Hashes with SHA-256 and encodes the digest as unpadded base64url (RFC 4648 §5), the encoding of the JWK
 * thumbprint (RFC 7638 §3).
 *
 * @param input Bytes, or a string hashed as its UTF-8 encoding.
 * @returns The 43-character digest.
 */
export async function sha256Base64url(input: Uint8Array | string): Promise<string> {
  // Web Crypto takes a view over an ArrayBuffer; a copy also accepts a view over a SharedArrayBuffer.
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64urlEncode(new Uint8Array(digest));
}
