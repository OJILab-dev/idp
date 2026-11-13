// The discovery document and the JWKS. Both are derived from the issuer and the configured keys, so they never
// advertise an algorithm the IdP cannot sign with (docs/design/standards-compliance.md, the Discovery row).
import type { JwkSet, JwsAlgorithm } from "@idp/jws";
import type { ProviderMetadata } from "@idp/oidc-discovery";
import type { Issuer } from "@idp/core/issuer";
import type { SigningKeySet } from "./signing-keys.js";

/** The OpenID Provider Metadata the IdP publishes, with each member narrowed to the value it always has. */
export type DiscoveryDocument = ProviderMetadata & {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
  readonly jwks_uri: string;
  /** RP-Initiated Logout 1.0 §2.1; the endpoint accepts GET and POST (§2). */
  readonly end_session_endpoint: string;
  readonly response_types_supported: readonly ["code"];
  readonly subject_types_supported: readonly ["public"];
  readonly grant_types_supported: readonly ["authorization_code"];
  readonly response_modes_supported: readonly ["query"];
  readonly request_uri_parameter_supported: false;
  readonly request_parameter_supported: false;
  readonly claims_parameter_supported: false;
  readonly code_challenge_methods_supported: readonly ["S256"];
  readonly token_endpoint_auth_methods_supported: readonly ["client_secret_basic", "none"];
  readonly authorization_response_iss_parameter_supported: true;
  readonly scopes_supported: readonly ["openid", "profile"];
  readonly id_token_signing_alg_values_supported: readonly JwsAlgorithm[];
};

/**
 * Lists the ID token signing algorithms the configured keys support: Ed25519 always, RS256 with an RSA key.
 *
 * @param keys The configured keys.
 * @returns `["Ed25519"]` or `["Ed25519", "RS256"]`.
 */
export function idTokenSigningAlgorithms(keys: SigningKeySet): readonly JwsAlgorithm[] {
  return keys.rsa === undefined ? ["Ed25519"] : ["Ed25519", "RS256"];
}

/**
 * Builds the discovery document.
 *
 * The members whose omission would mean support under OIDC Discovery 1.0 §3 (grant types, response modes,
 * request_uri) are stated explicitly, and optional members for unimplemented features are left out.
 *
 * @param issuer The issuer; every endpoint URL is derived from it.
 * @param keys The configured keys.
 * @returns The document to serve at `/.well-known/openid-configuration`.
 */
export function buildDiscoveryDocument(issuer: Issuer, keys: SigningKeySet): DiscoveryDocument {
  return {
    issuer: issuer.url,
    authorization_endpoint: `${issuer.url}/authorize`,
    token_endpoint: `${issuer.url}/token`,
    userinfo_endpoint: `${issuer.url}/userinfo`,
    jwks_uri: `${issuer.url}/jwks`,
    end_session_endpoint: `${issuer.url}/end_session`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    grant_types_supported: ["authorization_code"],
    response_modes_supported: ["query"],
    request_uri_parameter_supported: false,
    request_parameter_supported: false,
    claims_parameter_supported: false,
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    authorization_response_iss_parameter_supported: true,
    scopes_supported: ["openid", "profile"],
    id_token_signing_alg_values_supported: idTokenSigningAlgorithms(keys),
  };
}

/**
 * Builds the JWKS: every configured key, current and previous, with only its public members, kid, alg, and use.
 *
 * @param keys The configured keys.
 * @returns The document to serve at `/jwks`.
 */
export function buildJwks(keys: SigningKeySet): JwkSet {
  // publicJwk is built member by member at load time, so no private member can be present to leak.
  return { keys: keys.all.map((key) => key.publicJwk) };
}
