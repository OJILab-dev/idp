// User-facing use cases (OIDC, passkey sign-in and enrollment, self-service on the account page).
// The IdP Worker imports only this module and src/shared; importing src/admin is a lint error.

export {
  AUTH_CODE_LIFETIME_SECONDS,
  AUTHORIZE_REQUEST_LIFETIME_SECONDS,
  authorize,
  resumeAuthorize,
  type AuthorizeDecision,
  type AuthorizeErrorPageReason,
  type AuthorizeInput,
  type AuthorizeRedirectError,
  type ResumeInput,
} from "./authorize.js";
export { CorruptRowError, loadClient, type RegisteredClient } from "./clients.js";
export { cryptoRandomSource, systemClock, type Clock, type OidcDeps, type RandomSource } from "./deps.js";
export { asUiLocale, selectUiLocale, type UiLocale } from "./locale.js";
export { isRegisteredRedirectUri, matchesRegisteredRedirectUri } from "./redirect-uri.js";
export { findActiveSession, hasAccess, logout, type ActiveSession } from "./sessions.js";
export {
  exchangeToken,
  type TokenErrorCode,
  type TokenInput,
  type TokenResponse,
  type TokenSuccessBody,
} from "./token.js";
export { userinfo, type UserinfoClaims, type UserinfoInput, type UserinfoResponse } from "./userinfo.js";
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
