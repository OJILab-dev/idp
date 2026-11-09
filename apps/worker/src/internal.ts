// The IdP Worker's internal entrypoint for the admin Worker's Service Binding (docs/design/idpctl.md, RS256). A
// binding call does not come from Cloudflare's edge: it has no request.cf and no CF-Connecting-IP, so it cannot pass
// the public fetch path's TLS and rate-limit checks, and those checks must not be loosened by anything a client can
// send (a header, a path). The admin Worker therefore calls this RPC method instead, which only a binding to this
// named entrypoint can reach, and which computes the discovery document with the same code as /.well-known.
import { WorkerEntrypoint } from "cloudflare:workers";
import { buildDiscoveryDocument, type DiscoveryDocument } from "@idp/core/user";
import { workerConfig, type Env } from "./config.js";

/**
 * Computes the discovery document the public endpoint would serve for this environment.
 *
 * @param env The Worker's environment.
 * @returns The discovery document, built from the validated configuration.
 * @throws {InvalidConfigError} The configuration is invalid; the caller treats any failure as RS256 disabled.
 */
export async function discoveryFor(env: Env): Promise<DiscoveryDocument> {
  const { issuer, keys } = await workerConfig(env);
  return buildDiscoveryDocument(issuer, keys);
}

/** The named entrypoint the admin Worker's `IDP` Service Binding targets; it is never routed from the internet. */
export class IdpInternal extends WorkerEntrypoint<Env> {
  /**
   * Returns the discovery document, so the admin Worker can tell whether RS256 ID tokens are enabled.
   *
   * @returns The same document as `GET /.well-known/openid-configuration`.
   * @throws {InvalidConfigError} The IdP Worker's configuration is invalid.
   */
  async discovery(): Promise<DiscoveryDocument> {
    return discoveryFor(this.env);
  }
}
