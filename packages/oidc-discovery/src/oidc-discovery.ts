// OpenID Connect Discovery 1.0: the OpenID Provider Metadata document (§3) and where a Relying Party finds it (§4).
// The metadata type lists every member §3 defines, with the optionality §3 gives it, plus the members later
// specifications add to the same document and that a provider commonly publishes: the logout endpoint of
// RP-Initiated Logout 1.0 §2.1, PKCE methods (RFC 8414 §2), and the iss response parameter (RFC 9207 §3).

/** The path, under the issuer, of the OpenID Provider Configuration document (Discovery 1.0 §4). */
export const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

/**
 * Gives the URL of an issuer's OpenID Provider Configuration document: the issuer with any trailing "/" removed,
 * followed by the well-known path (Discovery 1.0 §4.1).
 *
 * @param issuer The issuer identifier, an https URL without query or fragment.
 * @returns The configuration URL.
 */
export function openIdConfigurationUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, "")}${OPENID_CONFIGURATION_PATH}`;
}

/** The OpenID Provider Metadata document (Discovery 1.0 §3); a provider narrows the members it publishes. */
export type ProviderMetadata = {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  /** Required unless only the implicit flow is used. */
  readonly token_endpoint?: string;
  readonly userinfo_endpoint?: string;
  readonly jwks_uri: string;
  readonly registration_endpoint?: string;
  readonly scopes_supported?: readonly string[];
  readonly response_types_supported: readonly string[];
  /** Absent means ["query", "fragment"]. */
  readonly response_modes_supported?: readonly string[];
  /** Absent means ["authorization_code", "implicit"]. */
  readonly grant_types_supported?: readonly string[];
  readonly acr_values_supported?: readonly string[];
  readonly subject_types_supported: readonly string[];
  readonly id_token_signing_alg_values_supported: readonly string[];
  readonly id_token_encryption_alg_values_supported?: readonly string[];
  readonly id_token_encryption_enc_values_supported?: readonly string[];
  readonly userinfo_signing_alg_values_supported?: readonly string[];
  readonly userinfo_encryption_alg_values_supported?: readonly string[];
  readonly userinfo_encryption_enc_values_supported?: readonly string[];
  readonly request_object_signing_alg_values_supported?: readonly string[];
  readonly request_object_encryption_alg_values_supported?: readonly string[];
  readonly request_object_encryption_enc_values_supported?: readonly string[];
  /** Absent means ["client_secret_basic"]. */
  readonly token_endpoint_auth_methods_supported?: readonly string[];
  readonly token_endpoint_auth_signing_alg_values_supported?: readonly string[];
  readonly display_values_supported?: readonly string[];
  readonly claim_types_supported?: readonly string[];
  readonly claims_supported?: readonly string[];
  readonly service_documentation?: string;
  readonly claims_locales_supported?: readonly string[];
  readonly ui_locales_supported?: readonly string[];
  /** Absent means false. */
  readonly claims_parameter_supported?: boolean;
  /** Absent means false. */
  readonly request_parameter_supported?: boolean;
  /** Absent means true. */
  readonly request_uri_parameter_supported?: boolean;
  /** Absent means false. */
  readonly require_request_uri_registration?: boolean;
  readonly op_policy_uri?: string;
  readonly op_tos_uri?: string;
  /** Where the RP sends the user to log out (RP-Initiated Logout 1.0 §2.1). */
  readonly end_session_endpoint?: string;
  /** The PKCE code challenge methods supported (RFC 8414 §2). */
  readonly code_challenge_methods_supported?: readonly string[];
  /** Whether authorization responses carry the iss parameter (RFC 9207 §3). */
  readonly authorization_response_iss_parameter_supported?: boolean;
};
