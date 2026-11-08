// The HTTP rules every route shares: the response headers, the cookies, and the same-origin check
// (docs/design/security-checklist.md, "セッションと通信").
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Issuer } from "@idp/core/shared";

// _headers covers the static pages; Worker responses need the same headers set in code (free-tier.md).
const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  // The only HTML the Worker renders is the error page, which needs nothing but its stylesheet.
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "cross-origin-opener-policy": "same-origin",
  // Codes, tokens, and error pages are per request; discovery and the JWKS change with a key rotation deploy.
  "cache-control": "no-store",
};

/**
 * Returns the response with the security headers set and every CORS header removed, whatever route produced it.
 *
 * @param response The response from the router.
 * @returns A response with mutable headers.
 */
export function withSecurityHeaders(response: Response): Response {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  // No endpoint takes part in CORS (standards-compliance.md, "例外：CORS に対応しない").
  for (const name of [...out.headers.keys()]) if (name.startsWith("access-control-")) out.headers.delete(name);
  return out;
}

/** The cookies the IdP sets. Each is sent as `__Host-<name>`: Secure, Path=/, and no Domain. */
export const COOKIES = {
  /** The session token (docs/design/tokens.md); set by the passkey sign-in. */
  session: "session",
  /** The ID of the authorize request saved while the user signs in (authentication.md, step 4). */
  authorizeRequest: "authorize_request",
} as const;

type CookieName = (typeof COOKIES)[keyof typeof COOKIES];

/**
 * Reads a `__Host-` cookie.
 *
 * @returns The value, or `undefined` when absent.
 */
export function readCookie(c: Context, name: CookieName): string | undefined {
  return getCookie(c, name, "host");
}

/**
 * Sets a `__Host-` cookie with HttpOnly and SameSite=Lax, so a cross-site POST to /authorize carries no session
 * and always falls through to a passkey sign-in.
 *
 * @param maxAge Seconds until the browser drops it; it should not outlive the row it names.
 */
export function writeCookie(c: Context, name: CookieName, value: string, maxAge: number): void {
  setCookie(c, name, value, { prefix: "host", path: "/", secure: true, httpOnly: true, sameSite: "Lax", maxAge });
}

/** Clears a `__Host-` cookie. */
export function clearCookie(c: Context, name: CookieName): void {
  deleteCookie(c, `__Host-${name}`, { path: "/", secure: true, httpOnly: true, sameSite: "Lax" });
}

/**
 * Checks that a cookie-authenticated, state-changing request comes from the issuer's own pages: `Sec-Fetch-Site`
 * must be `same-origin`, or, without it, `Origin` must equal the issuer. A request with neither is refused.
 *
 * @returns Whether the request may proceed.
 */
export function isSameOrigin(request: Request, issuer: Issuer): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null) return site === "same-origin";
  return request.headers.get("origin") === issuer.origin;
}

/**
 * The stricter check for a cookie-authenticated GET (`/webauthn/credentials`): only `Sec-Fetch-Site: same-origin`
 * passes. `Origin` cannot stand in for it, because a same-origin GET may carry none (authentication.md, the account
 * page).
 *
 * @returns Whether the request may proceed.
 */
export function isSameOriginFetch(request: Request): boolean {
  return request.headers.get("sec-fetch-site") === "same-origin";
}

// A WebAuthn response is a few kilobytes at most, and so is any legitimate /authorize or /token form; anything far
// larger is not a request of the pages or of an RP.
const BODY_LIMIT_BYTES = 64 * 1024;

function mediaTypeOf(request: Request): string | undefined {
  return (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
}

/**
 * Reads a body as UTF-8 text, at most {@link BODY_LIMIT_BYTES} bytes.
 *
 * The limit is enforced on the bytes as they arrive, not on Content-Length alone: a chunked body declares no length,
 * and buffering it whole first would let one request hold the isolate's memory. A declared length over the limit is
 * refused before anything is read.
 *
 * @returns The text, or `undefined` when the body is over the limit.
 */
async function readLimitedText(request: Request): Promise<string | undefined> {
  const declared = request.headers.get("content-length");
  if (declared !== null && !(Number(declared) <= BODY_LIMIT_BYTES)) return undefined;
  if (request.body === null) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > BODY_LIMIT_BYTES) {
      // Stop the upload instead of draining it; the rest of the body is never read.
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Reads an `application/json` body that is a JSON object.
 *
 * @returns The object, or `undefined` when the body has another media type, exceeds the limit, does not parse, or is
 *   not an object.
 */
export async function readJsonObject(request: Request): Promise<Readonly<Record<string, unknown>> | undefined> {
  if (mediaTypeOf(request) !== "application/json") return undefined;
  const text = await readLimitedText(request);
  if (text === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

/**
 * Reads an `application/x-www-form-urlencoded` body in the order received, repeats included.
 *
 * @returns The pairs, or `undefined` when the body is another media type or exceeds the limit.
 */
export async function readForm(request: Request): Promise<readonly (readonly [string, string])[] | undefined> {
  if (mediaTypeOf(request) !== "application/x-www-form-urlencoded") return undefined;
  const text = await readLimitedText(request);
  return text === undefined ? undefined : [...new URLSearchParams(text)];
}

/** One structured line per request (docs/design/deployment.md, "ログ"); never a token, cookie, body, or IP address. */
export function log(fields: Readonly<Record<string, unknown>>): void {
  console.log(JSON.stringify(fields));
}
