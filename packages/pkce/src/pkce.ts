// Proof Key for Code Exchange (RFC 7636) with the S256 method: the shape of a code verifier, the derivation of its
// code challenge, and the shape of a challenge an authorization server is asked to store. Which methods a server
// accepts is the server's policy; this module only knows S256.
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "@idp/base64url";

// A code verifier is 43 to 128 unreserved characters (RFC 7636 §4.1).
const CODE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

// A SHA-256 digest is 32 bytes, which is 43 characters of unpadded base64url (RFC 7636 §4.2).
const S256_CHALLENGE_LENGTH = 43;

/**
 * Tells whether a value has the shape of a code verifier: 43 to 128 characters from the unreserved set
 * `A-Z a-z 0-9 - . _ ~` (RFC 7636 §4.1).
 *
 * @param value The untrusted input.
 * @returns Whether the value can be a code verifier.
 */
export function isCodeVerifier(value: string): boolean {
  return CODE_VERIFIER.test(value);
}

/**
 * Derives the S256 code challenge of a verifier: the unpadded base64url of the SHA-256 of its ASCII bytes
 * (RFC 7636 §4.2).
 *
 * @param verifier A value for which {@link isCodeVerifier} holds; its characters are ASCII, so UTF-8 is ASCII.
 * @returns The 43-character challenge.
 */
export async function s256CodeChallenge(verifier: string): Promise<string> {
  return base64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

/**
 * Tells whether a value has the shape of an S256 code challenge: 43 characters of canonical unpadded base64url, so it
 * encodes exactly 32 bytes (RFC 7636 §4.2).
 *
 * @param value The untrusted input.
 * @returns Whether the value can be an S256 code challenge.
 */
export function isS256CodeChallenge(value: string): boolean {
  if (value.length !== S256_CHALLENGE_LENGTH) return false;
  try {
    base64urlDecode(value);
    return true;
  } catch (error) {
    if (error instanceof InvalidBase64urlError) return false;
    throw error;
  }
}
