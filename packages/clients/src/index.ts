// Which redirect URIs and post-logout redirect URIs a client may register.
export {
  POST_LOGOUT_REDIRECT_URI_RULES,
  classifyRedirectUri,
  isPostLogoutRedirectUriRegistrable,
  isRedirectUriAllowed,
  type ClientType,
} from "./redirect-uri-registration.js";
