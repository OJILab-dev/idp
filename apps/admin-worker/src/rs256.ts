// Whether RS256 ID tokens are enabled, read from the IdP Worker's discovery document over a Service Binding
// (docs/design/deployment.md, "署名鍵"). The admin Worker binds no signing key, so discovery is the one place that
// says which algorithms the IdP Worker signs with; anything it cannot read counts as disabled (fail-closed).
//
// The binding targets the IdP Worker's internal RPC entrypoint (IdpInternal), not its public fetch handler: a binding
// call has no request.cf.tlsVersion and no CF-Connecting-IP, so the public path's TLS and rate-limit checks refuse it.
import type { Issuer } from "@idp/core/issuer";
import type { IdpInternalBinding } from "./config.js";

/**
 * Asks the IdP Worker whether it advertises RS256 for ID tokens.
 *
 * @param idp The Service Binding to the IdP Worker's internal entrypoint; undefined when not bound.
 * @param issuer The issuer; the discovery document must name it, so a misrouted binding is not trusted.
 * @param log Receives the reason when the answer is not a clear yes.
 * @returns True only for a discovery document of this issuer whose `id_token_signing_alg_values_supported` lists
 *   `RS256`; never throws.
 */
export async function rs256Enabled(idp: IdpInternalBinding | undefined, issuer: Issuer, log: (reason: string) => void): Promise<boolean> {
  if (idp === undefined) {
    log("no IDP binding");
    return false;
  }
  try {
    const doc = await idp.discovery();
    const fields = typeof doc === "object" && doc !== null ? (doc as Record<string, unknown>) : undefined;
    const algs = fields?.["id_token_signing_alg_values_supported"];
    if (fields?.["issuer"] !== issuer.url || !Array.isArray(algs)) {
      log("discovery document is not this issuer's");
      return false;
    }
    return algs.includes("RS256");
  } catch (error) {
    log(`discovery failed: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}
