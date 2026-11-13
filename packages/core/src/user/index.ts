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
export { CorruptRowError, loadClient, loadLogoutClient, type LogoutClient, type RegisteredClient } from "./clients.js";
export {
  endSession,
  type EndSessionDecision,
  type EndSessionErrorReason,
  type EndSessionInput,
  type EndSessionVia,
} from "./end-session.js";
export { cryptoRandomSource, systemClock, type Clock, type OidcDeps, type PasskeyDeps, type RandomSource } from "./deps.js";
export {
  CHALLENGE_LIFETIME_SECONDS,
  type CreationOptionsJson,
  type CredentialDescriptorJson,
  type PasskeyRejection,
  type PasskeyRejectionReason,
  type RequestOptionsJson,
} from "./webauthn/ceremony.js";
export { listOwnPasskeys, type OwnPasskey, type OwnPasskeysResult } from "./webauthn/credentials.js";
export { enrollOptions, enrollVerify, type EnrollOptionsResult, type EnrollVerifyResult } from "./webauthn/enroll.js";
export {
  addBegin,
  addOptions,
  addVerify,
  revokeBegin,
  revokeVerify,
  type AddOptionsResult,
  type AddVerifyResult,
  type ReauthOptionsResult,
  type RevokeVerifyResult,
} from "./webauthn/self-service.js";
export {
  signInOptions,
  signInVerify,
  type SignInOptionsResult,
  type SignInVerifyInput,
  type SignInVerifyResult,
} from "./webauthn/sign-in.js";
export { asUiLocale, selectUiLocale, type UiLocale } from "./locale.js";
export { isRegisteredRedirectUri, matchesRegisteredRedirectUri } from "./redirect-uri.js";
export { SESSION_LIFETIME_SECONDS, findActiveSession, hasAccess, logout, type ActiveSession } from "./sessions.js";
export {
  exchangeToken,
  type TokenErrorCode,
  type TokenInput,
  type TokenResponse,
  type TokenSuccessBody,
} from "./token.js";
export { userinfo, type UserinfoClaims, type UserinfoInput, type UserinfoResponse } from "./userinfo.js";
export { buildDiscoveryDocument, buildJwks, idTokenSigningAlgorithms, type DiscoveryDocument } from "./discovery.js";
export {
  InvalidSigningKeyConfigError,
  loadSigningKeys,
  type SigningKey,
  type SigningKeySecrets,
  type SigningKeySet,
} from "./signing-keys.js";
export {
  InvalidTokenError,
  SigningAlgorithmUnavailableError,
  TOKEN_LIFETIME_SECONDS,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  verifyIdTokenHint,
  verifyLogoutIdTokenHint,
  type AccessTokenClaims,
  type LogoutIdTokenHint,
  type AccessTokenInput,
  type GrantedScope,
  type IdTokenClaims,
  type IdTokenInput,
  type JwtType,
  type VerifiedAccessToken,
} from "./tokens.js";
