// Whether RS256 ID tokens are enabled, read from the IdP Worker's discovery over a Service Binding
// (docs/design/deployment.md, "署名鍵"). The admin Worker binds no signing key, so discovery is the one place that
// says which algorithms the IdP Worker signs with; anything it cannot read counts as disabled (fail-closed).
import type { Issuer } from "@idp/core/shared";

/**
 * Asks the IdP Worker whether it advertises RS256 for ID tokens.
 *
 * @param idp The Service Binding to the IdP Worker; undefined when not bound.
 * @param issuer The issuer; the discovery document must name it, so a misrouted binding is not trusted.
 * @param log Receives the reason when the answer is not a clear yes.
 * @returns True only for a 200 discovery document of this issuer whose `id_token_signing_alg_values_supported`
 *   lists `RS256`; never throws.
 */
export async function rs256Enabled(idp: Fetcher | undefined, issuer: Issuer, log: (reason: string) => void): Promise<boolean> {
  if (idp === undefined) {
    log("no IDP binding");
    return false;
  }
  try {
    const response = await idp.fetch(new Request(`${issuer.url}/.well-known/openid-configuration`));
    if (response.status !== 200) {
      log(`discovery answered ${response.status}`);
      return false;
    }
    const doc = (await response.json()) as Record<string, unknown> | null;
    const algs = doc?.["id_token_signing_alg_values_supported"];
    if (doc?.["issuer"] !== issuer.url || !Array.isArray(algs)) {
      log("discovery document is not this issuer's");
      return false;
    }
    return algs.includes("RS256");
  } catch (error) {
    log(`discovery failed: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}
