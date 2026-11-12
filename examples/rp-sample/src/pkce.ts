// The random values of one login (state, nonce, PKCE verifier) and the PKCE S256 challenge (RFC 7636).
import { base64urlEncode } from "./encoding.js";

/**
 * A fresh 256-bit random value as 43 base64url characters. Used for state, nonce, and the PKCE verifier: base64url is
 * within the verifier's unreserved characters and 43 is its minimum length (RFC 7636 §4.1).
 *
 * @returns The random value.
 */
export function randomToken(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The S256 code challenge: BASE64URL(SHA256(ASCII(code_verifier))) (RFC 7636 §4.2).
 *
 * @param verifier The code verifier.
 * @returns The code challenge.
 */
export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64urlEncode(new Uint8Array(digest));
}
