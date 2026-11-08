// The IdP Worker: the OIDC endpoints and the /webauthn/* API. The three pages (sign-in,
// enrollment, account) are static assets served before the Worker runs (docs/design/free-tier.md).
import { cryptoRandomSource, systemClock } from "@idp/core/user";
import { createApp, type AppOptions } from "./app.js";
import type { Env } from "./config.js";
import { withSecurityHeaders } from "./http.js";

export type { Env } from "./config.js";

/** The Worker's fetch handler. */
export type Handler = {
  readonly fetch: (request: Request, env: Env, ctx: ExecutionContext) => Promise<Response>;
};

/**
 * Builds the Worker's fetch handler.
 *
 * @param options The clock and the random source; the system ones unless a test fixes them.
 * @returns The handler; the security headers are set on the way out, so no route can omit them.
 */
export function createHandler(options: AppOptions = { clock: systemClock, random: cryptoRandomSource }): Handler {
  const app = createApp(options);
  return {
    fetch: async (request, env, ctx) => withSecurityHeaders(await app.fetch(request, env, ctx)),
  };
}

export default createHandler() satisfies ExportedHandler<Env>;
