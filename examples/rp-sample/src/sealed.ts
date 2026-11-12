// Sealed cookie values: AES-256-GCM with a fresh 96-bit IV per value, so a value is both secret and
// integrity-protected. The cookie's name is the associated data, so a value sealed for one cookie (the login flow)
// cannot be replayed as another (the session). The expiry is inside the sealed payload; the cookie's Max-Age only
// helps the browser forget it.
import { ConfigError } from "./errors.js";
import { base64urlDecode, base64urlEncode, parseJsonObject } from "./encoding.js";

const VERSION = "v1";
const IV_BYTES = 12;

/**
 * Imports SESSION_KEY: exactly 32 bytes as standard base64 (what `openssl rand -base64 32` prints).
 *
 * @param value The secret's value.
 * @returns A non-extractable AES-GCM key.
 * @throws {ConfigError} The value is missing or not 32 bytes of base64; the error never contains the value.
 */
export async function importSealingKey(value: string | undefined): Promise<CryptoKey> {
  let bytes: Uint8Array | undefined;
  if (value !== undefined && /^[A-Za-z0-9+/]{43}=$/.test(value)) {
    bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }
  if (bytes?.length !== 32) throw new ConfigError("SESSION_KEY must be 32 bytes as base64");
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Seals a payload for one cookie.
 *
 * @param key The sealing key.
 * @param purpose The cookie's name, bound as associated data.
 * @param payload The JSON payload.
 * @param expiresAt Unix seconds after which unseal refuses the value.
 * @returns The cookie value: `v1.<iv>.<ciphertext>` in base64url.
 */
export async function seal(key: CryptoKey, purpose: string, payload: Readonly<Record<string, unknown>>, expiresAt: number): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify({ exp: expiresAt, data: payload }));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(purpose) }, key, plaintext);
  return `${VERSION}.${base64urlEncode(iv)}.${base64urlEncode(new Uint8Array(ciphertext))}`;
}

/**
 * Opens a sealed value.
 *
 * @param key The sealing key.
 * @param purpose The cookie's name; must be the one the value was sealed for.
 * @param value The cookie value, untrusted.
 * @param now Unix seconds.
 * @returns The payload, or undefined when the value is malformed, tampered with, sealed for another cookie or with
 *   another key, or expired. Never throws for a bad value: a bad cookie is the same as no cookie.
 */
export async function unseal(key: CryptoKey, purpose: string, value: string | undefined, now: number): Promise<Record<string, unknown> | undefined> {
  const [version, ivText, ciphertextText, extra] = (value ?? "").split(".");
  if (version !== VERSION || extra !== undefined || ivText === undefined || ciphertextText === undefined) return undefined;
  const iv = base64urlDecode(ivText);
  const ciphertext = base64urlDecode(ciphertextText);
  if (iv?.length !== IV_BYTES || ciphertext === undefined) return undefined;
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(purpose) }, key, ciphertext);
  } catch {
    return undefined;
  }
  const sealed = parseJsonObject(new TextDecoder().decode(plaintext));
  if (sealed === undefined || typeof sealed.exp !== "number" || now >= sealed.exp) return undefined;
  const data = sealed.data;
  return typeof data === "object" && data !== null && !Array.isArray(data) ? (data as Record<string, unknown>) : undefined;
}
