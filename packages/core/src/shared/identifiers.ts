// Formats of the identifiers and random values fixed by docs/design/cross-language-contract.md.
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "./base64url.js";

const RANDOM_TOKEN_BYTES = 32;

// 32 bytes are 256 bits, which unpadded base64url writes in 43 characters.
const RANDOM_TOKEN_LENGTH = 43;

// Lowercase only: the contract fixes one spelling so that IDs compare as plain strings (RFC 9562 §4 allows both cases).
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const CLIENT_ID = /^[a-z0-9](?:[a-z0-9-]{1,62})[a-z0-9]$/;

/**
 * Generates a token or secret: 32 random bytes as unpadded base64url.
 *
 * @returns A 43-character string that satisfies {@link isRandomTokenFormat}.
 */
export function randomToken(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(RANDOM_TOKEN_BYTES)));
}

/**
 * Checks the shape of a token, secret, or Idempotency-Key: exactly 32 bytes as canonical unpadded base64url.
 *
 * @param value The untrusted input.
 * @returns Whether the value has the contract format; it says nothing about whether the token exists.
 */
export function isRandomTokenFormat(value: string): boolean {
  if (value.length !== RANDOM_TOKEN_LENGTH) return false;
  try {
    base64urlDecode(value);
    return true;
  } catch (error) {
    if (error instanceof InvalidBase64urlError) return false;
    throw error;
  }
}

/**
 * Checks for a lowercase, hyphenated UUIDv4 (RFC 9562 §5.4), the form of user and group IDs.
 *
 * @param value The untrusted input.
 * @returns Whether the version nibble is 4 and the variant is RFC 9562's (8 to b).
 */
export function isUuidV4(value: string): boolean {
  return UUID_V4.test(value);
}

/**
 * Generates a UUIDv4 in the contract's lowercase, hyphenated form.
 *
 * @returns A string that satisfies {@link isUuidV4}.
 */
export function newUuidV4(): string {
  return crypto.randomUUID();
}

// WebAuthn Level 3 §5.4.3 (rawId) caps a credential ID at 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES = 1023;

/**
 * Checks a WebAuthn credential ID as stored in credentials.id: 1 to 1023 bytes as canonical unpadded base64url.
 *
 * @param value The untrusted input.
 * @returns Whether the value is a well-formed credential ID; it says nothing about whether the passkey exists.
 */
export function isCredentialId(value: string): boolean {
  try {
    const bytes = base64urlDecode(value);
    return bytes.length > 0 && bytes.length <= MAX_CREDENTIAL_ID_BYTES;
  } catch (error) {
    if (error instanceof InvalidBase64urlError) return false;
    throw error;
  }
}

/**
 * Checks a client ID: 3 to 64 lowercase letters, digits, or hyphens, starting and ending with a letter or digit.
 *
 * @param value The untrusted input.
 * @returns Whether the value is a well-formed client ID; it says nothing about whether the client exists.
 */
export function isClientId(value: string): boolean {
  return CLIENT_ID.test(value);
}
