// The admin Worker: the admin API behind the RFC 9421 signature and the signing-key allowlist (docs/design/idpctl.md).
import { createApp } from "./app.js";
import type { Env } from "./config.js";

export type { Env } from "./config.js";

const app = createApp();

/**
 * Handles every request to the admin host.
 *
 * Cache-Control: no-store is set here, on the way out, so no response (a secret, a list, a refusal) can be cached
 * whichever path produced it (idpctl.md, "IdP が発行する秘密の扱い").
 */
async function fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const response = await app.fetch(request, env, ctx);
  const out = new Response(response.body, response);
  out.headers.set("cache-control", "no-store");
  return out;
}

export default { fetch } satisfies ExportedHandler<Env>;
