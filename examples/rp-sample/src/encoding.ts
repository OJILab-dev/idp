// base64url without padding (RFC 4648 §5), the encoding of JWS segments, PKCE values, and the sealed cookies.

/**
 * Encodes bytes as unpadded base64url.
 *
 * @param bytes The bytes.
 * @returns The base64url text.
 */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * Decodes unpadded base64url. Only the canonical alphabet is accepted, so one value has one encoding.
 *
 * @param text The base64url text.
 * @returns The bytes, or undefined when the text is not base64url.
 */
export function base64urlDecode(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return undefined;
  try {
    const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/**
 * Parses a JSON object, refusing anything else.
 *
 * @param text The JSON text.
 * @returns The object, or undefined when the text is not a JSON object.
 */
export function parseJsonObject(text: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
