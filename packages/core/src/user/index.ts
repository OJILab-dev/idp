// User-facing use cases (OIDC, passkey sign-in and enrollment, self-service on the account page).
// The IdP Worker imports only this module and src/shared; importing src/admin is a lint error.

export { buildDiscoveryDocument, buildJwks, idTokenSigningAlgorithms, type DiscoveryDocument, type Jwks } from "./discovery.js";
export {
  InvalidTokenError,
  signJwt,
  verifyJws,
  type JwsHeader,
  type JwsVerificationOptions,
  type JwtType,
  type VerifiedJws,
} from "./jws.js";
export {
  InvalidSigningKeyConfigError,
  loadSigningKeys,
  type Ed25519PublicJwk,
  type JwsAlgorithm,
  type PublicJwk,
  type RsaPublicJwk,
  type SigningKey,
  type SigningKeySecrets,
  type SigningKeySet,
} from "./signing-keys.js";
export {
  SigningAlgorithmUnavailableError,
  TOKEN_LIFETIME_SECONDS,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  verifyIdTokenHint,
  type AccessTokenClaims,
  type AccessTokenInput,
  type GrantedScope,
  type IdTokenClaims,
  type IdTokenInput,
  type VerifiedAccessToken,
} from "./tokens.js";
