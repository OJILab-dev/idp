import { base64urlEncode } from "./base64url.js";

/**
 * Hashes with SHA-256 and encodes the digest as unpadded base64url, the contract's hash format.
 *
 * The same format serves token and secret hashes, the PKCE S256 challenge (RFC 7636 §4.2), and the JWK
 * thumbprint (RFC 7638 §3), so one function covers all of them.
 *
 * @param input Bytes, or a string hashed as its UTF-8 encoding.
 * @returns The 43-character digest.
 */
export async function sha256Base64url(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64urlEncode(new Uint8Array(digest));
}
