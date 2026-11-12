// The errors that decide how the Worker answers. Each carries a short reason for the log; none carries a secret,
// a token, or a value the IdP sent.

/** A missing or malformed setting: the Worker answers 500. The message names the setting, never its value. */
export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

/** The IdP answered something this RP must not trust (discovery, token, JWKS, or /userinfo): the Worker answers 502. */
export class IdpError extends Error {
  override readonly name = "IdpError";
}
