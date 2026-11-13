// A minimal sample relying party for this IdP: login, logout, and an account page (examples/rp-sample/README.md).
// It is a reference for real RPs, deployed beside the IdP but never imported by it.
import { createApp, type AppOptions } from "./app.js";
import type { Env } from "./config.js";
import { CONTENT_SECURITY_POLICY } from "./html.js";

export type { Env } from "./config.js";

/** The Worker's fetch handler. */
export type Handler = {
  readonly fetch: (request: Request, env: Env) => Promise<Response>;
};

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  // Pages hold personal data and responses set session cookies: never cache them.
  "cache-control": "no-store",
  // The callback URL carries the code and state; no page may leak its URL in a Referer.
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "strict-transport-security": "max-age=31536000",
};

function withSecurityHeaders(response: Response): Response {
  const secured = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) secured.headers.set(name, value);
  // Only the logout page sets a CSP of its own (logoutContentSecurityPolicy: one hashed script and a form post to
  // the IdP); every other response gets the scriptless default.
  if (!secured.headers.has("content-security-policy")) secured.headers.set("content-security-policy", CONTENT_SECURITY_POLICY);
  return secured;
}

function systemNow(): number {
  return Math.floor(Date.now() / 1000);
}

function systemFetch(request: Request): Promise<Response> {
  return fetch(request);
}

/**
 * Builds the Worker's fetch handler.
 *
 * @param options The outbound fetch and the clock; the Worker's own unless a test replaces them.
 * @returns The handler; the security headers are set on the way out, so no route can omit them.
 */
export function createHandler(options: AppOptions = { fetch: systemFetch, now: systemNow }): Handler {
  const app = createApp(options);
  return {
    fetch: async (request, env) => withSecurityHeaders(await app.fetch(request, env)),
  };
}

export default createHandler() satisfies ExportedHandler<Env>;
